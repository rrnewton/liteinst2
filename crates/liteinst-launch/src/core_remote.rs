//! Restricted remote publication of genuine A1 CPUID plans.
//!
//! The core emits `ReplaceFirst`; the child callback executes native CPUID and
//! writes its four outputs into the saved context. This is not a no-op that
//! silently skips the selected instruction. A real compiled callback supplies
//! the numeric address, and separately authenticated child code occupies that
//! exact address. No tracee address becomes a local pointer or function value.
//!
//! This adapter requires a real held Linux x86-64 execution owner, the same
//! qualified host layout as the emitter, no CET/AMX, immutable code and
//! exhaustive entry/resume facts. It supports only generalized puns and refuses
//! interacting source dependencies. Task rendezvous and first-fault arbitration
//! belong to the execution owner. This adapter does not implement A2
//! composition, application signal delivery, or the full B1 contract.

use std::collections::BTreeSet;
use std::mem::{offset_of, size_of};
use std::ops::Range;
use std::rc::Rc;
use std::time::{Duration, Instant};

use iced_x86::{Decoder, DecoderOptions};
use liteinst_admission::scan::{Candidate, CandidateKind, SiteClass};
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, LegalEntrySet, PatchPlan,
    PlanKind, PublicationReceipt, QuiescenceLease, Refusal, ResumeObligation,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, PlannedInstall, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::{
    HookCallback, HookContext, SavedExtendedStateDescriptor, SavedExtendedStateFormat,
    SavedExtendedStateLayout,
};

use crate::publication::{PublicationOperations, PublicationStop};
use crate::{LaunchError, MemoryMapping, RegisterSnapshot, SignalStop};

const PAGE: u64 = 4096;
const MAX_SOURCE: usize = 19; // Five consumed bytes plus at most fourteen tail bytes.
/// Maximum selected plans retained for one remote publication transaction.
pub const MAX_CPUID_BUNDLE: usize = 64;
const RED_ZONE: u64 = 128;

/// Exact, caller-certified source facts for one literal two-byte CPUID.
pub struct CpuidPlanRequest<'a> {
    /// Non-reusable source mapping/content/policy identity.
    pub identity: CodeIdentity,
    /// Original CPUID address, also the start of `code`.
    pub address: u64,
    /// Five through nineteen bytes, ending at a complete instruction boundary.
    pub code: &'a [u8],
    /// Exhaustive entries and saved resumes, authenticated separately from decoding.
    pub entries: &'a LegalEntrySet,
    /// Bounded candidate placement; child availability is checked at publication.
    pub allocation: &'a AllocationPolicy,
}

/// Pure core plan and exact emitted image; constructing it changes no mappings.
#[derive(Clone, Debug)]
pub struct PreparedCpuid {
    prepared: PlannedInstall,
}

impl PreparedCpuid {
    /// Plans a generalized pun without widening the core's observing allowlist.
    pub fn prepare(request: CpuidPlanRequest<'_>) -> Result<Self, Refusal> {
        if !(5..=MAX_SOURCE).contains(&request.code.len())
            || request.code.get(..2) != Some([0x0f, 0xa2].as_slice())
            || request.entries.identity != request.identity
            || request.entries.completeness == EntryCompleteness::Incomplete
            || request.entries.resumes == ResumeObligation::Unresolved
        {
            return Err(Refusal::UnresolvedEntry);
        }
        let source = AddressRange::new(request.address, request.code.len())?;
        if !request.entries.scope.covers(source) {
            return Err(Refusal::InvalidRange);
        }
        let mut decoder = Decoder::with_ip(64, request.code, request.address, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid()
                || instruction.next_ip() > source.end()
                || !request
                    .entries
                    .entries
                    .iter()
                    .any(|entry| entry.address == instruction.ip() && !entry.requires_endbr)
            {
                return Err(Refusal::NotInstructionHead);
            }
        }
        if decoder.position() != request.code.len() {
            return Err(Refusal::NotInstructionHead);
        }
        let block = AddressRange::new(request.address, 2)?;
        let prepared = plan_install(&InstallRequest {
            identity: request.identity,
            code: request.code,
            base_address: request.address,
            function: source,
            block,
            logical_pc: request.address,
            entries: request.entries,
            hook: callback_marker as HookCallback,
            semantics: HookSemantics::ReplaceFirst,
            allocation: request.allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::GeneralizedPunOnly,
                max_upstream_bytes: 0,
                max_displaced_bytes: 2,
                max_sites: 1,
            },
        })?;
        let parts = prepared.plan().parts();
        if !matches!(&parts.kind, PlanKind::GeneralizedPun(pun) if pun.instruction_len == 2)
            || parts.logical_pc != request.address
            || parts.physical_pc != request.address
            || parts.requirements.sigill_router
            || parts
                .obligations
                .iter()
                .any(|entry| !matches!(entry, EntryObligation::Preserved(_)))
            || parts.allocations.len() != 1
            || parts.generated.len() != 1
        {
            return Err(Refusal::InvalidPlan);
        }
        Ok(Self { prepared })
    }

    /// Exact immutable core plan, including every expected read and source edit.
    pub fn plan(&self) -> &PatchPlan {
        self.prepared.plan()
    }

    /// All five original bytes fetched by the generalized E9 encoding.
    pub fn consumed(&self) -> AddressRange {
        match &self.plan().parts().kind {
            PlanKind::GeneralizedPun(pun) => pun.consumed,
            PlanKind::Relocation => unreachable!("constructor accepts only generalized puns"),
        }
    }
}

// This is a genuine, permanently callable local function. Its machine code is
// never copied to, or called on behalf of, the child. Only its numeric address
// is emitted by the core; the separately proven stub implements the child ABI.
#[inline(never)]
unsafe extern "C" fn callback_marker(_: *mut HookContext) {}

fn marker_address() -> u64 {
    callback_marker as HookCallback as usize as u64
}

fn callback_bytes() -> Vec<u8> {
    let mut bytes = vec![0xcc, 0x53]; // Observation stop; preserve callee-saved RBX.
    for (opcode, offset) in [
        ([0x8b, 0x87], offset_of!(HookContext, rax)), // mov eax,[rdi+rax]
        ([0x8b, 0x8f], offset_of!(HookContext, rcx)), // mov ecx,[rdi+rcx]
    ] {
        bytes.extend_from_slice(&opcode);
        bytes.extend_from_slice(&(offset as u32).to_le_bytes());
    }
    bytes.extend_from_slice(&[0x0f, 0xa2]);
    // CPUID writes EAX/EBX/ECX/EDX, zero-extending each architectural result.
    // Store full-width results; the emitter restores them into application GPRs.
    for (modrm, offset) in [
        (0x87, offset_of!(HookContext, rax)),
        (0x9f, offset_of!(HookContext, rbx)),
        (0x8f, offset_of!(HookContext, rcx)),
        (0x97, offset_of!(HookContext, rdx)),
    ] {
        bytes.extend_from_slice(&[0x48, 0x89, modrm]);
        bytes.extend_from_slice(&(offset as u32).to_le_bytes());
    }
    bytes.extend_from_slice(&[0x5b, 0xc3]); // Restore RBX; return to core restoration.
    bytes
}

#[derive(Clone, Debug)]
struct CodeImage {
    range: Range<u64>,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct CallbackImage {
    pid: libc::pid_t,
    address: u64,
    code: CodeImage,
}

/// A pre-CPUID observation recovered from the authenticated core callback frame.
#[derive(Clone, Debug)]
pub struct CpuidObservation {
    /// Original selected instruction, not the generated callback PC.
    pub site: Candidate,
    /// Saved application GPRs/flags; segment state comes from the held task.
    /// `orig_rax` remains kernel trap bookkeeping, not a saved application GPR.
    pub registers: RegisterSnapshot,
    /// Actual architectural xstate before the native CPUID callback body runs.
    pub xstate: Vec<u8>,
}

/// One completed remote publication. Drop deliberately does not unmap code.
#[derive(Clone, Debug)]
pub struct InstalledCpuid {
    prepared: PreparedCpuid,
    receipt: PublicationReceipt,
    callback: Rc<CallbackImage>,
    generated: CodeImage,
}

impl InstalledCpuid {
    /// Exact completed core plan and source dependency lock.
    pub fn plan(&self) -> &PatchPlan {
        self.receipt.plan()
    }

    /// Receipt issued only after final permissions and target-process sync-core.
    pub fn receipt(&self) -> &PublicationReceipt {
        &self.receipt
    }

    /// Original CPUID address.
    pub fn logical_pc(&self) -> u64 {
        self.plan().parts().logical_pc
    }

    /// Authenticates and acknowledges the current pre-CPUID callback trap.
    ///
    /// The task remains stopped after INT3. Its next resume executes native
    /// CPUID once and returns through the unchanged core restore sequence.
    pub fn observe<S: PublicationStop>(
        &self,
        stop: &mut S,
        signal: &SignalStop,
    ) -> Result<CpuidObservation, LaunchError> {
        let (actual, context) = callback_context(stop, signal, &self.callback)?;
        verify_code_stop(stop, &self.generated)?;
        for read in &self.plan().parts().reads {
            if stop.read_memory(read.address, read.bytes.len())?
                != patched_read(self.plan(), read.address, &read.bytes)?
            {
                return invalid("published CPUID source changed");
            }
        }
        let logical_pc = field(&context, offset_of!(HookContext, instruction_pointer));
        if logical_pc != self.logical_pc() {
            return invalid("callback context belongs to a different CPUID plan");
        }
        let layout = self.prepared.prepared.image().layout();
        let extended = layout.saved_extended_state;
        let descriptor_at = size_of::<HookContext>() - size_of::<SavedExtendedStateDescriptor>();
        let saved_address = field(&context, descriptor_at);
        if field(&context, descriptor_at + 8) != extended.len()
            || field(&context, descriptor_at + 16) != extended.mask()
            || field(&context, descriptor_at + 24) != extended.format().raw()
        {
            return invalid("callback saved-state descriptor differs from emitted layout");
        }
        let alignment = if extended.format() == SavedExtendedStateFormat::FXSAVE64 {
            16
        } else if extended.format() == SavedExtendedStateFormat::XSAVE64_STANDARD {
            64
        } else {
            return invalid("callback has unsupported saved-state format");
        };
        let application_rsp = field(&context, offset_of!(HookContext, stack_pointer));
        if actual
            .rdi
            .checked_add(size_of::<HookContext>() as u64 + RED_ZONE)
            != Some(application_rsp)
            || (actual.rdi & !(alignment - 1)).checked_sub(extended.len()) != Some(saved_address)
            || actual.rsp.checked_add(8) != Some(saved_address)
        {
            return invalid("callback stack geometry differs from core frame");
        }
        let stack_bottom = actual
            .rsp
            .checked_sub(8)
            .ok_or(LaunchError::Invalid("callback stack underflow"))?;
        require_permissions(
            &stop.mappings(),
            stack_bottom..application_rsp,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::PROT_EXEC,
        )?;
        let image = self.prepared.prepared.image();
        let return_address = image
            .address()
            .checked_add(layout.relocated_prefix_len as u64)
            .and_then(|pc| pc.checked_add(layout.entry_stop_len as u64))
            .and_then(|pc| pc.checked_add(layout.instrumentation_len as u64))
            .ok_or(LaunchError::Invalid("callback return address overflow"))?;
        if !self.generated.range.contains(&return_address)
            || word(&stop.read_memory(actual.rsp, 8)?) != return_address
        {
            return invalid("callback return does not enter the exact generated image");
        }
        let mut registers = actual;
        macro_rules! restore_fields {
            ($($name:ident),+ $(,)?) => {
                $(registers.$name = field(&context, offset_of!(HookContext, $name));)+
            };
        }
        restore_fields!(
            rax, rbx, rcx, rdx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15
        );
        registers.rip = logical_pc;
        registers.rsp = application_rsp;
        registers.eflags = field(&context, offset_of!(HookContext, rflags));
        let xstate = stop.read_xstate()?;
        stop.acknowledge_owned_signal(signal)?;
        Ok(CpuidObservation {
            site: Candidate {
                address: logical_pc,
                len: 2,
                class: SiteClass::Cpuid,
                kind: CandidateKind::KnownInstruction,
            },
            registers,
            xstate,
        })
    }
}

/// Per-child callback ownership and append-only source dependency locks.
///
/// Use one publisher for exactly one owned process lifetime, never a reused PID.
/// Code allocations remain owned by that child until its termination.
#[derive(Default)]
pub struct CpuidPublisher {
    callback: Option<Rc<CallbackImage>>,
    installed: Vec<InstalledCpuid>,
}

impl CpuidPublisher {
    /// All successful publications; their expected reads remain byte-locked.
    pub fn installed(&self) -> &[InstalledCpuid] {
        &self.installed
    }

    /// The private child callback address, once it has been published.
    pub fn callback_address(&self) -> Option<u64> {
        self.callback.as_ref().map(|callback| callback.address)
    }

    /// Resolves and authenticates the shared callback stop without exposing an
    /// unauthenticated logical-PC lookup to the admission loop.
    pub fn observe<S: PublicationStop>(
        &self,
        stop: &mut S,
        signal: &SignalStop,
    ) -> Result<CpuidObservation, LaunchError> {
        let callback = self
            .callback
            .as_ref()
            .ok_or(LaunchError::Invalid("no CPUID callback is installed"))?;
        let (_, context) = callback_context(stop, signal, callback)?;
        let logical = field(&context, offset_of!(HookContext, instruction_pointer));
        self.installed
            .iter()
            .find(|installed| installed.logical_pc() == logical)
            .ok_or(LaunchError::Invalid(
                "callback logical PC has no installed plan",
            ))?
            .observe(stop, signal)
    }

    /// Publishes a disjoint bundle while a real stopped-task lease remains held.
    /// `finalize` restores permissions for the complete scanned page bundle,
    /// including every page touched by each five-byte consumed range. The
    /// adapter checks final permissions and completes target sync-core itself.
    ///
    /// # Safety
    /// The caller certifies current identity, complete legal entries and saved
    /// continuations, immutable private code, no other readers/writers/aliases,
    /// and sole ownership of the child's execution and mapping lifecycle. Every
    /// task sharing the target address space must remain excluded throughout
    /// publication; the selected worker may execute only trusted island code. The
    /// child must have the emitter's exact enabled extended-state layout, native
    /// System V ABI, no CET or AMX use, and sufficient mapped writable callback
    /// stack below its preserved red zone. Code and instrumentation-private
    /// stack may not be inspected as application data. Application control may
    /// enter generated code only through published entries, never the callback
    /// or syscall island directly. No application signal handlers/delivery are
    /// supported. The finalizer must not execute application code or change
    /// source identity/bytes. These are owner proofs, not consequences of `/proc`.
    pub unsafe fn publish_bundle<S: PublicationStop>(
        &mut self,
        stop: &mut S,
        prepared: &[PreparedCpuid],
        current_identity: CodeIdentity,
        timeout: Duration,
        finalize: impl FnOnce(&mut dyn PublicationOperations) -> Result<(), LaunchError>,
    ) -> Result<Vec<InstalledCpuid>, LaunchError> {
        if prepared.is_empty() || prepared.len() > MAX_CPUID_BUNDLE {
            return invalid("invalid CPUID publication bundle size");
        }
        if timeout.is_zero() || timeout > crate::MAX_LAUNCH_TIMEOUT {
            return invalid("invalid CPUID publication deadline");
        }
        let deadline = Instant::now() + timeout;
        for (index, new) in prepared.iter().enumerate() {
            if new.plan().parts().identity != current_identity {
                return invalid("CPUID plan identity differs from current source");
            }
            for old in &self.installed {
                check_disjoint(new.plan(), old.plan())?;
            }
            for prior in &prepared[..index] {
                check_disjoint(new.plan(), prior.plan())?;
            }
        }
        let callback_before = self.callback.clone();
        if callback_before
            .as_ref()
            .is_some_and(|callback| callback.pid != stop.pid())
        {
            return invalid("CPUID publisher belongs to a different child");
        }
        let callback_code = if let Some(callback) = &callback_before {
            callback.code.clone()
        } else {
            padded_image(marker_address(), &callback_bytes(), None)?
        };
        let mut ranges = Vec::new();
        ranges.push(core_range(callback_code.range.clone())?);
        for item in prepared {
            ranges.extend(item.plan().parts().dependencies.iter().copied());
            ranges.extend(
                item.plan()
                    .parts()
                    .allocations
                    .iter()
                    .map(|request| request.range),
            );
            let store = pun_store(item.plan())?;
            // The exact native writer additionally reads its neighboring words
            // to verify that the hardware store changed no adjacent byte.
            let envelope = word_envelope(store.address, store.bytes.len())?;
            ranges.push(core_range(envelope)?);
        }
        // SAFETY: the caller supplies the complete owner proofs above. The
        // helper's guard borrows the actual stopped child, exposes only narrow
        // publication operations, and kills on any error or unwind.
        let installed = unsafe {
            stop.with_publication_lease(current_identity, ranges, |operations, lease| {
                let mut transaction = PoisonOnFailure {
                    lease,
                    complete: false,
                };
                let registers = operations.read_registers()?;
                let xstate = operations.read_xstate()?;
                if registers.cs != 0x33 || operations.page_size() != PAGE as usize {
                    return invalid("CPUID publication requires native 4-KiB-page process");
                }
                let layout = SavedExtendedStateLayout::detect()
                    .map_err(|_| LaunchError::Invalid("cannot qualify emitter xstate layout"))?;
                for item in prepared {
                    check_lease(transaction.lease, item.plan())?;
                    if !item
                        .plan()
                        .parts()
                        .allocations
                        .iter()
                        .all(|allocation| transaction.lease.covers(allocation.range))
                    {
                        return invalid("core lease does not cover generated CPUID allocation");
                    }
                    if item.prepared.image().layout().saved_extended_state != layout {
                        return invalid("CPUID emitter xstate layout changed since planning");
                    }
                    verify_reads(operations, item.plan(), false)?;
                }
                if !transaction
                    .lease
                    .covers(core_range(callback_code.range.clone())?)
                {
                    return invalid("core lease does not cover CPUID callback allocation");
                }
                let callback = if let Some(callback) = callback_before {
                    verify_code_ops(operations, &callback.code)?;
                    callback
                } else {
                    let address = marker_address();
                    let code = callback_code;
                    map_code(operations, &code, deadline)?;
                    Rc::new(CallbackImage {
                        pid: operations.pid(),
                        address,
                        code,
                    })
                };
                let mut generated = Vec::with_capacity(prepared.len());
                for item in prepared {
                    let parts = item.plan().parts();
                    let image = &parts.generated[0];
                    let allocation = parts.allocations[0].range;
                    let code = padded_image(image.address, &image.bytes, Some(allocation))?;
                    map_code(operations, &code, deadline)?;
                    generated.push(code);
                }
                // Remote allocation executes only the trusted island. Verify
                // its preserved state and every source again before source writes.
                verify_registers(operations, &registers, &xstate)?;
                for item in prepared {
                    check_lease(transaction.lease, item.plan())?;
                    verify_reads(operations, item.plan(), false)?;
                }
                let mut writable_pages = BTreeSet::new();
                for item in prepared {
                    let store = pun_store(item.plan())?;
                    let envelope = word_envelope(store.address, store.bytes.len())?;
                    for page in (envelope.start & !(PAGE - 1)..envelope.end).step_by(PAGE as usize)
                    {
                        writable_pages.insert(page);
                    }
                }
                for page in writable_pages {
                    operations.mprotect(
                        page,
                        PAGE as usize,
                        libc::PROT_READ | libc::PROT_WRITE,
                        remaining(deadline)?,
                    )?;
                }
                for item in prepared {
                    let store = pun_store(item.plan())?;
                    let expected = original_bytes(item.plan(), store.address, store.bytes.len())?;
                    operations.exact_store_checked(
                        store.address,
                        expected,
                        &store.bytes,
                        remaining(deadline)?,
                    )?;
                }
                finalize(operations)?;
                for item in prepared {
                    check_lease(transaction.lease, item.plan())?;
                    verify_reads(operations, item.plan(), true)?;
                    let consumed = item.consumed();
                    require_permissions(
                        &operations.mappings(),
                        consumed.start()..consumed.end(),
                        libc::PROT_EXEC,
                        libc::PROT_WRITE,
                    )?;
                }
                verify_code_ops(operations, &callback.code)?;
                for code in &generated {
                    verify_code_ops(operations, code)?;
                }
                operations.sync_core(remaining(deadline)?)?;
                verify_registers(operations, &registers, &xstate)?;
                let completed = prepared
                    .iter()
                    .cloned()
                    .zip(generated)
                    .map(|(prepared, generated)| {
                        // SAFETY: the trusted plan's exact source/native store,
                        // allocations and preserved entries have been verified;
                        // final executable permissions and target sync-core are
                        // complete under the real generation-bound exclusion.
                        let receipt = PublicationReceipt::completed(prepared.plan().clone());
                        InstalledCpuid {
                            prepared,
                            receipt,
                            callback: callback.clone(),
                            generated,
                        }
                    })
                    .collect::<Vec<_>>();
                transaction.complete = true;
                Ok(completed)
            })
        }?;
        self.callback = Some(installed[0].callback.clone());
        self.installed.extend(installed.iter().cloned());
        Ok(installed)
    }
}

struct PoisonOnFailure<'a, 'guard> {
    lease: &'a mut QuiescenceLease<'guard>,
    complete: bool,
}

impl Drop for PoisonOnFailure<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.lease.poison();
        }
    }
}

fn check_disjoint(left: &PatchPlan, right: &PatchPlan) -> Result<(), LaunchError> {
    if left.parts().logical_pc == right.parts().logical_pc {
        return invalid("CPUID source site is already owned");
    }
    for (writer, reader) in [(left, right), (right, left)] {
        let store = pun_store(writer)?;
        let write = AddressRange::new(store.address, store.bytes.len())
            .map_err(|_| LaunchError::Invalid("invalid CPUID store range"))?;
        if reader
            .parts()
            .dependencies
            .iter()
            .any(|range| range.overlaps(write))
        {
            return invalid("CPUID plans have interacting source dependencies");
        }
    }
    Ok(())
}

fn pun_store(plan: &PatchPlan) -> Result<&liteinst2::contracts::ByteEdit, LaunchError> {
    match &plan.parts().kind {
        PlanKind::GeneralizedPun(pun) if pun.instruction_len == 2 => Ok(&pun.store),
        _ => invalid("remote CPUID adapter requires a two-byte generalized pun"),
    }
}

fn check_lease(lease: &QuiescenceLease<'_>, plan: &PatchPlan) -> Result<(), LaunchError> {
    lease
        .check(plan)
        .map_err(|_| LaunchError::Invalid("CPUID core lease check failed"))
}

fn original_bytes(plan: &PatchPlan, address: u64, len: usize) -> Result<&[u8], LaunchError> {
    let range = AddressRange::new(address, len)
        .map_err(|_| LaunchError::Invalid("invalid CPUID expected-byte range"))?;
    for read in &plan.parts().reads {
        if AddressRange::new(read.address, read.bytes.len())
            .is_ok_and(|source| source.covers(range))
        {
            let offset = (address - read.address) as usize;
            return Ok(&read.bytes[offset..offset + len]);
        }
    }
    invalid("CPUID store lacks complete original bytes")
}

fn patched_read(plan: &PatchPlan, address: u64, original: &[u8]) -> Result<Vec<u8>, LaunchError> {
    let mut expected = original.to_vec();
    let source = AddressRange::new(address, expected.len())
        .map_err(|_| LaunchError::Invalid("invalid CPUID read range"))?;
    let store = pun_store(plan)?;
    let write = AddressRange::new(store.address, store.bytes.len())
        .map_err(|_| LaunchError::Invalid("invalid CPUID store range"))?;
    if !source.covers(write) {
        return invalid("CPUID read does not contain its exact store");
    }
    let offset = (store.address - address) as usize;
    expected[offset..offset + store.bytes.len()].copy_from_slice(&store.bytes);
    Ok(expected)
}

fn verify_reads(
    operations: &dyn PublicationOperations,
    plan: &PatchPlan,
    patched: bool,
) -> Result<(), LaunchError> {
    for read in &plan.parts().reads {
        let expected = if patched {
            patched_read(plan, read.address, &read.bytes)?
        } else {
            read.bytes.clone()
        };
        if operations.read_memory(read.address, expected.len())? != expected {
            return invalid("CPUID expected source bytes changed");
        }
    }
    Ok(())
}

fn verify_registers(
    operations: &dyn PublicationOperations,
    registers: &RegisterSnapshot,
    xstate: &[u8],
) -> Result<(), LaunchError> {
    if operations.read_registers()? != *registers || operations.read_xstate()? != xstate {
        return invalid("CPUID publication changed application register state");
    }
    Ok(())
}

fn padded_image(
    address: u64,
    bytes: &[u8],
    allocation: Option<AddressRange>,
) -> Result<CodeImage, LaunchError> {
    let end = address
        .checked_add(bytes.len() as u64)
        .ok_or(LaunchError::Invalid("code image overflow"))?;
    let range = if let Some(allocation) = allocation {
        allocation.start()..allocation.end()
    } else {
        (address & !(PAGE - 1))
            ..end
                .checked_add(PAGE - 1)
                .ok_or(LaunchError::Invalid("code image page overflow"))?
                & !(PAGE - 1)
    };
    if bytes.is_empty()
        || range.start % PAGE != 0
        || range.end % PAGE != 0
        || range.start > address
        || range.end < end
        || range.end - range.start > crate::MAX_MEMORY_READ as u64
    {
        return invalid("code image does not fit a bounded whole-page allocation");
    }
    let mut image = vec![0xcc; (range.end - range.start) as usize];
    let offset = (address - range.start) as usize;
    image[offset..offset + bytes.len()].copy_from_slice(bytes);
    Ok(CodeImage {
        range,
        bytes: image,
    })
}

fn map_code(
    operations: &mut dyn PublicationOperations,
    code: &CodeImage,
    deadline: Instant,
) -> Result<(), LaunchError> {
    if operations.map_private_code(code.range.start, &code.bytes, remaining(deadline)?)?
        != code.range
    {
        return invalid("remote code allocation returned a different address");
    }
    verify_code_ops(operations, code)
}

fn verify_code_ops(
    operations: &dyn PublicationOperations,
    code: &CodeImage,
) -> Result<(), LaunchError> {
    require_permissions(
        &operations.mappings(),
        code.range.clone(),
        libc::PROT_READ | libc::PROT_EXEC,
        libc::PROT_WRITE,
    )?;
    if operations.read_memory(code.range.start, code.bytes.len())? != code.bytes {
        return invalid("immutable remote code image changed");
    }
    Ok(())
}

fn verify_code_stop<S: PublicationStop>(stop: &S, code: &CodeImage) -> Result<(), LaunchError> {
    require_permissions(
        &stop.mappings(),
        code.range.clone(),
        libc::PROT_READ | libc::PROT_EXEC,
        libc::PROT_WRITE,
    )?;
    if stop.read_memory(code.range.start, code.bytes.len())? != code.bytes {
        return invalid("immutable remote code image changed");
    }
    Ok(())
}

fn callback_context<S: PublicationStop>(
    stop: &S,
    signal: &SignalStop,
    callback: &CallbackImage,
) -> Result<(RegisterSnapshot, Vec<u8>), LaunchError> {
    if size_of::<HookContext>() != 176
        || size_of::<SavedExtendedStateDescriptor>() != 32
        || offset_of!(HookContext, rflags) != 136
        || callback.pid != stop.pid()
        || signal.signal != libc::SIGTRAP
        || !matches!(signal.code, libc::SI_KERNEL | libc::TRAP_BRKPT)
        || signal.instruction_pointer != callback.address + 1
    {
        return invalid("stop is not the owned CPUID callback trap");
    }
    verify_code_stop(stop, &callback.code)?;
    let registers = stop.read_registers()?;
    if registers.rip != signal.instruction_pointer
        || registers.cs != 0x33
        || registers.orig_rax != u64::MAX
        || registers.rdi != registers.r12
        || registers.rdi % 8 != 0
    {
        return invalid("CPUID callback registers do not identify a native core frame");
    }
    let end = registers
        .rdi
        .checked_add(size_of::<HookContext>() as u64)
        .ok_or(LaunchError::Invalid("callback context overflow"))?;
    require_permissions(
        &stop.mappings(),
        registers.rdi..end,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::PROT_EXEC,
    )?;
    let context = stop.read_memory(registers.rdi, size_of::<HookContext>())?;
    Ok((registers, context))
}

fn require_permissions(
    mappings: &[MemoryMapping],
    range: Range<u64>,
    required: i32,
    forbidden: i32,
) -> Result<(), LaunchError> {
    if range.start >= range.end {
        return invalid("empty remote permission proof");
    }
    let mut cursor = range.start;
    while cursor < range.end {
        let mapping = mappings
            .iter()
            .find(|mapping| mapping.start <= cursor && cursor < mapping.end)
            .ok_or(LaunchError::Invalid("remote proof range is unmapped"))?;
        let bytes = mapping.permissions.as_bytes();
        if bytes.len() != 4 || bytes[3] != b'p' {
            return invalid("remote proof range is not private");
        }
        let protection = if bytes[0] == b'r' { libc::PROT_READ } else { 0 }
            | if bytes[1] == b'w' {
                libc::PROT_WRITE
            } else {
                0
            }
            | if bytes[2] == b'x' { libc::PROT_EXEC } else { 0 };
        if protection & required != required || protection & forbidden != 0 {
            return invalid("remote proof range has incorrect permissions");
        }
        cursor = mapping.end.min(range.end);
    }
    Ok(())
}

fn word_envelope(address: u64, len: usize) -> Result<Range<u64>, LaunchError> {
    let end = address
        .checked_add(len as u64)
        .and_then(|end| end.checked_add(7))
        .ok_or(LaunchError::Invalid("native store envelope overflow"))?
        & !7;
    Ok((address & !7)..end)
}

fn core_range(range: Range<u64>) -> Result<AddressRange, LaunchError> {
    AddressRange::new(range.start, (range.end - range.start) as usize)
        .map_err(|_| LaunchError::Invalid("invalid held native-store envelope"))
}

fn field(bytes: &[u8], offset: usize) -> u64 {
    word(&bytes[offset..offset + 8])
}

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(
        bytes
            .try_into()
            .expect("validated fixed-width context field"),
    )
}

fn remaining(deadline: Instant) -> Result<Duration, LaunchError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or(LaunchError::Timeout("remote CPUID publication"))
}

fn invalid<T>(message: &'static str) -> Result<T, LaunchError> {
    Err(LaunchError::Invalid(message))
}
