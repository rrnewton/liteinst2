//! Generation-bound install-once rewriting of caller-certified basic blocks.
//!
//! This path uses a scoped quiescence lease and Linux sync-core. It never uses
//! the legacy concurrent publisher's empirical staleness budget. See
//! `INTERFACES.md` for the caller's mapping, entry, signal, and ABI obligations.

use std::io::Read;

use iced_x86::{FlowControl, Mnemonic};

use crate::contracts::*;
use crate::planner::HookSemantics;
use crate::scanner::{InstructionScanner, ScanResult};
use crate::trampoline::{ExecutableTrampoline, HookCallback, TrampolineImage, TrampolinePlan};

/// Bounded same-block search. Bounds are refusals, never permission to skip sites.
#[derive(Clone, Copy, Debug)]
pub struct SearchPolicy {
    /// Maximum backward distance from logical to physical PC.
    pub max_upstream_bytes: usize,
    /// Maximum whole-instruction displaced interval.
    pub max_displaced_bytes: usize,
    /// Maximum physical instruction heads considered.
    pub max_sites: usize,
}
impl Default for SearchPolicy {
    fn default() -> Self {
        Self {
            max_upstream_bytes: 64,
            max_displaced_bytes: 80,
            max_sites: 65,
        }
    }
}

/// Permitted executable placement and explicit search/memory budgets.
#[derive(Clone, Debug)]
pub struct AllocationPolicy {
    /// Every complete allocated page must lie in one of these ranges.
    pub ranges: Vec<AddressRange>,
    /// First target to try (constraints may change its displacement bytes).
    pub preferred_address: Option<u64>,
    /// Bound on generated address candidates per physical site.
    pub max_candidates: usize,
    /// Maximum new executable mappings; this implementation needs one.
    pub max_mappings: usize,
    /// Maximum newly allocated executable backing bytes.
    pub max_mapped_bytes: usize,
}
impl AllocationPolicy {
    /// Permits an ordinary near mapping within signed rel32 reach.
    pub fn near(address: u64) -> Result<Self, Refusal> {
        let next = address.checked_add(5).ok_or(Refusal::InvalidRange)?;
        let low = next.saturating_sub(1 << 31).max(0x1_0000);
        let high = next
            .checked_add(i32::MAX as u64)
            .ok_or(Refusal::InvalidRange)?;
        Ok(Self {
            ranges: vec![AddressRange::new(low, (high - low) as usize)?],
            preferred_address: None,
            max_candidates: 256,
            max_mappings: 1,
            max_mapped_bytes: 8192,
        })
    }
}

/// Authenticated snapshot and facts needed by the quiescent planner.
pub struct InstallRequest<'a> {
    /// Non-reusable original mapping identity.
    pub identity: CodeIdentity,
    /// Exact bytes; the entire supplied range becomes a read dependency.
    pub code: &'a [u8],
    /// Executable address corresponding to code[0].
    pub base_address: u64,
    /// Caller-certified containing function.
    pub function: AddressRange,
    /// Caller-certified containing basic block; upstream search cannot leave it.
    pub block: AddressRange,
    /// Original instruction at which the callback belongs.
    pub logical_pc: u64,
    /// Exhaustive static and dynamic entry facts.
    pub entries: &'a LegalEntrySet,
    /// Non-unwinding System V callback, under the documented state contract.
    pub hook: HookCallback,
    /// Observe, or replace the logical instruction only.
    pub semantics: HookSemantics,
    /// Permitted allocations and resource limits.
    pub allocation: &'a AllocationPolicy,
    /// Bounded site search.
    pub search: SearchPolicy,
}

/// One bounded physical-site search result.
#[derive(Clone, Debug)]
pub struct SiteAttempt {
    /// Candidate physical PC.
    pub physical_pc: u64,
    /// None means this physical site was selected.
    pub refusal: Option<Refusal>,
}

/// Measured plan shape (no host-dependent performance claim).
#[derive(Clone, Debug)]
pub struct PlanMetrics {
    /// Logical minus physical PC.
    pub upstream_bytes: usize,
    /// Whole original instruction bytes displaced.
    pub displaced_bytes: usize,
    /// Instructions executed before the logical hook.
    pub prefix_instructions: usize,
    /// Addresses examined for this selected candidate.
    pub allocation_attempts: usize,
    /// Ordered site attempts including refusals.
    pub attempts: Vec<SiteAttempt>,
}

/// Pure plan and emitted image; no executable mapping has been changed.
#[derive(Clone, Debug)]
pub struct PlannedInstall {
    plan: PatchPlan,
    image: TrampolineImage,
    metrics: PlanMetrics,
}
impl PlannedInstall {
    /// Shared immutable contract consumed by admission.
    pub const fn plan(&self) -> &PatchPlan {
        &self.plan
    }
    /// Generated image, exact entry routes, and architectural comparison boundaries.
    pub const fn image(&self) -> &TrampolineImage {
        &self.image
    }
    /// Search outcomes and displaced shape.
    pub const fn metrics(&self) -> &PlanMetrics {
        &self.metrics
    }

    /// Publishes this permanent interception under a held dependency lease.
    ///
    /// # Safety
    /// `writable_base` must alias the complete original read snapshot and remain
    /// valid through retirement. The lease owner enforces all documented
    /// quiescence, alias, saved-context and signal contracts. Execution must
    /// meet the declared System V/no-CET ABI and have sufficient writable stack
    /// below the red zone for the callback and extended-state image.
    pub unsafe fn publish(
        &self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
    ) -> Result<(InstalledOnce, PublicationReceipt), PublicationFailure> {
        // SAFETY: forwarded from this entrypoint's contract.
        let mut publisher = unsafe { LivePublisher::new(self, writable_base) };
        publisher.publish_quiescent(&self.plan, lease)
    }
}

/// Failed planning with the attempted-site inventory retained.
#[derive(Clone, Debug)]
pub struct PlanningFailure {
    /// Final fail-closed reason.
    pub reason: Refusal,
    /// Ordered candidates and their precise failure reasons.
    pub attempts: Vec<SiteAttempt>,
}

/// Plans installation without writing source bytes or reserving executable memory.
pub fn plan_install(request: &InstallRequest<'_>) -> Result<PlannedInstall, Refusal> {
    plan_install_detailed(request).map_err(|failure| failure.reason)
}

/// Planning entrypoint retaining all bounded candidate refusal evidence.
pub fn plan_install_detailed(
    request: &InstallRequest<'_>,
) -> Result<PlannedInstall, PlanningFailure> {
    let mut attempts = Vec::new();
    let result = (|| {
        let source = AddressRange::new(request.base_address, request.code.len())?;
        if request.entries.identity != request.identity {
            return Err(Refusal::StaleGeneration);
        }
        if request.entries.completeness == EntryCompleteness::Incomplete
            || request.entries.resumes == ResumeObligation::Unresolved
        {
            return Err(Refusal::UnresolvedEntry);
        }
        if !source.covers(request.function)
            || !request.function.covers(request.block)
            || !request.block.contains(request.logical_pc)
            || !request.entries.scope.covers(request.block)
        {
            return Err(Refusal::InvalidRange);
        }
        qualify_host()?;
        let scan = InstructionScanner::default()
            .scan(request.code, request.base_address)
            .map_err(|e| Refusal::Backend(e.to_string()))?;
        if scan.site(request.logical_pc).is_none()
            || scan.site(request.block.start()).is_none()
            || (request.block.end() != source.end() && scan.site(request.block.end()).is_none())
        {
            return Err(Refusal::NotInstructionHead);
        }
        for entry in &request.entries.entries {
            if !request.entries.scope.contains(entry.address)
                || (source.contains(entry.address) && scan.site(entry.address).is_none())
            {
                return Err(Refusal::NotInstructionHead);
            }
        }
        if let ResumeObligation::Enumerated(pcs) = &request.entries.resumes {
            for &pc in pcs {
                if !request.entries.scope.contains(pc)
                    || (source.contains(pc) && scan.site(pc).is_none())
                {
                    return Err(Refusal::NotInstructionHead);
                }
            }
        }
        let occupied = occupied_ranges()?;
        let mut candidates: Vec<_> = scan
            .instructions()
            .iter()
            .filter(|i| {
                request.block.contains(i.address())
                    && i.address() <= request.logical_pc
                    && request.logical_pc - i.address() <= request.search.max_upstream_bytes as u64
            })
            .map(|i| i.address())
            .collect();
        candidates.reverse();
        // Same-site first; otherwise favor a single-cache-line store, then the
        // nearest upstream head. Quiescence is required for every placement.
        candidates.sort_by_key(|&pc| {
            (
                pc != request.logical_pc,
                pc % 64 > 56,
                request.logical_pc - pc,
            )
        });
        for physical in candidates.into_iter().take(request.search.max_sites) {
            match plan_at(request, &scan, source, physical, &occupied) {
                Ok(mut plan) => {
                    attempts.push(SiteAttempt {
                        physical_pc: physical,
                        refusal: None,
                    });
                    plan.metrics.attempts = attempts.clone();
                    return Ok(plan);
                }
                Err(reason) => attempts.push(SiteAttempt {
                    physical_pc: physical,
                    refusal: Some(reason),
                }),
            }
        }
        Err(attempts
            .last()
            .and_then(|attempt| attempt.refusal.clone())
            .unwrap_or(Refusal::NoPatchWindow))
    })();
    result.map_err(|reason| PlanningFailure { reason, attempts })
}

fn plan_at(
    request: &InstallRequest<'_>,
    scan: &ScanResult,
    source: AddressRange,
    physical: u64,
    occupied: &[AddressRange],
) -> Result<PlannedInstall, Refusal> {
    let mut end = physical;
    let mut instructions = Vec::new();
    for item in scan
        .instructions()
        .iter()
        .filter(|i| i.address() >= physical)
    {
        if item.address() >= request.block.end() {
            break;
        }
        end = item.address() + item.len() as u64;
        if end > request.block.end() || end - physical > request.search.max_displaced_bytes as u64 {
            return Err(Refusal::NoPatchWindow);
        }
        instructions.push(item);
        if end - physical >= 5 && end > request.logical_pc {
            break;
        }
    }
    if end - physical < 5 || end <= request.logical_pc {
        return Err(Refusal::NoPatchWindow);
    }
    let displaced = AddressRange::new(physical, (end - physical) as usize)?;
    for item in &instructions {
        let replaced = item.address() == request.logical_pc
            && request.semantics == HookSemantics::ReplaceFirst;
        if !replaced {
            qualify_instruction(item.instruction())?;
            if item.instruction().flow_control() != FlowControl::Next
                && item.address() + item.len() as u64 != end
            {
                return Err(Refusal::UnsupportedSemantics(
                    "control transfer before displaced end".into(),
                ));
            }
        }
    }
    // Positive direct targets in the supplied snapshot cannot be omitted even
    // by an erroneous Complete entry list. Alternate streams remain refused.
    let mut heads: Vec<u64> = request.entries.entries.iter().map(|e| e.address).collect();
    if request.entries.completeness == EntryCompleteness::AllInstructionHeads {
        heads.extend(instructions.iter().map(|i| i.address()));
    }
    if let ResumeObligation::Enumerated(pcs) = &request.entries.resumes {
        heads.extend(pcs);
    }
    for item in scan.instructions() {
        if matches!(
            item.instruction().op0_kind(),
            iced_x86::OpKind::NearBranch16
                | iced_x86::OpKind::NearBranch32
                | iced_x86::OpKind::NearBranch64
        ) {
            heads.push(item.instruction().near_branch_target());
        }
    }
    heads.retain(|&pc| displaced.contains(pc) && pc != physical);
    heads.sort_unstable();
    heads.dedup();
    if heads.iter().any(|&pc| scan.site(pc).is_none()) {
        return Err(Refusal::NotInstructionHead);
    }
    if request
        .entries
        .entries
        .iter()
        .any(|entry| displaced.contains(entry.address) && entry.requires_endbr)
    {
        return Err(Refusal::UnsupportedSemantics(
            "CET IBT landing pad in displaced range".into(),
        ));
    }
    let trampoline = TrampolinePlan::from_window(
        scan,
        physical,
        request.logical_pc,
        end,
        request.hook,
        request.semantics == HookSemantics::ReplaceFirst,
    )
    .map_err(|e| Refusal::Backend(e.to_string()))?;
    let mut mask = [false; 4];
    for &head in &heads {
        if head < physical + 5 {
            mask[(head - physical - 1) as usize] = true;
        }
    }
    let policy = request.allocation;
    if policy.max_mappings == 0 || policy.max_mapped_bytes < 4096 {
        return Err(Refusal::AllocationUnavailable);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut last_error = Refusal::AllocationUnavailable;
    for attempt in 0..policy.max_candidates {
        let Some(target) = candidate_target(physical, mask, policy.preferred_address, attempt)
        else {
            continue;
        };
        if !seen.insert(target) {
            continue;
        }
        let image = match trampoline.emit_at(target) {
            Ok(image) => image,
            Err(e) => {
                last_error = Refusal::Backend(e.to_string());
                continue;
            }
        };
        let page_start = target & !4095;
        let page_end = target
            .checked_add(image.bytes().len() as u64)
            .and_then(|x| x.checked_add(4095))
            .map(|x| x & !4095)
            .ok_or(Refusal::InvalidRange)?;
        let allocation = AddressRange::new(page_start, (page_end - page_start) as usize)?;
        if allocation.len() > policy.max_mapped_bytes as u64
            || !policy.ranges.iter().any(|range| range.covers(allocation))
            || occupied.iter().any(|range| range.overlaps(allocation))
        {
            continue;
        }
        let offset = (physical - source.start()) as usize;
        let mut patch = request.code[offset..offset + displaced.len() as usize].to_vec();
        patch[0] = 0xe9;
        let displacement = i32::try_from(i128::from(target) - i128::from(physical + 5))
            .map_err(|_| Refusal::AllocationUnavailable)?;
        patch[1..5].copy_from_slice(&displacement.to_le_bytes());
        // First choose the displacement. Interior head bytes are already illegal
        // opcodes encoded in that displacement and must never be overwritten.
        for &head in heads.iter().rev() {
            if head >= physical + 5 {
                let at = (head - physical) as usize;
                patch[at] = 0x62;
                let following = |delta: usize| {
                    patch.get(at + delta).copied().or_else(|| {
                        request
                            .code
                            .get((head - source.start()) as usize + delta)
                            .copied()
                    })
                };
                // In the declared legacy/EVEX envelope P1 bit 2 must be one.
                // Invalid EVEX may still fetch later bytes before raising #UD.
                // Keep its full architectural 15-byte fetch envelope in one
                // executable page and inside the authenticated snapshot; a
                // short suffix at a page boundary can otherwise raise #PF.
                if head % 4096 > 4096 - 15
                    || source.end() - head < 15
                    || following(1).is_none()
                    || !following(2).is_some_and(|p1| p1 & 4 == 0)
                {
                    patch[at] = 0x60; // PUSHA is unconditionally #UD in 64-bit mode.
                }
            }
        }
        let routes: Vec<_> = heads
            .iter()
            .map(|&head| {
                image
                    .entry_routes()
                    .iter()
                    .find(|&&(original, _)| original == head)
                    .map(|&(_, generated)| EntryRoute {
                        original: head,
                        generated,
                    })
                    .ok_or(Refusal::InvalidPlan)
            })
            .collect::<Result<_, _>>()?;
        let mut obligations = vec![EntryObligation::Preserved(physical)];
        obligations.extend(routes.iter().copied().map(EntryObligation::Routed));
        let plan = PatchPlan::checked(PlanParts {
            identity: request.identity,
            profile: ApplicationProfile::InstallOnce,
            logical_pc: request.logical_pc,
            physical_pc: physical,
            displaced,
            reads: vec![ExpectedBytes {
                address: source.start(),
                bytes: request.code.to_vec(),
            }],
            writes: vec![ByteEdit {
                address: physical,
                bytes: patch,
            }],
            dependencies: vec![source],
            entries: request.entries.clone(),
            obligations,
            allocations: vec![AllocationRequest {
                range: allocation,
                alignment: 4096,
            }],
            generated: vec![GeneratedCode {
                address: target,
                bytes: image.bytes().to_vec(),
                program_counters: image.program_counter_mappings().to_vec(),
            }],
            requirements: PublicationRequirements {
                quiescent: true,
                sync_core: true,
                sigill_router: !routes.is_empty(),
            },
        })?;
        return Ok(PlannedInstall {
            plan,
            image,
            metrics: PlanMetrics {
                upstream_bytes: (request.logical_pc - physical) as usize,
                displaced_bytes: displaced.len() as usize,
                prefix_instructions: instructions
                    .iter()
                    .filter(|i| i.address() < request.logical_pc)
                    .count(),
                allocation_attempts: attempt + 1,
                attempts: vec![],
            },
        });
    }
    Err(last_error)
}

// These single-byte opcodes are architecturally invalid in 64-bit mode. Do not
// add D4/D5: newer ISAs may assign prefixes to historically illegal opcodes.
const ILLEGAL: [u8; 14] = [
    0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61, 0xce,
];
fn candidate_target(
    physical: u64,
    mask: [bool; 4],
    preferred: Option<u64>,
    attempt: usize,
) -> Option<u64> {
    let next = physical.checked_add(5)?;
    let combinations = ILLEGAL
        .len()
        .checked_pow(mask.iter().filter(|&&v| v).count() as u32)?;
    let seed = preferred.unwrap_or(next.checked_add(0x1_0000)?);
    let seed = seed.checked_add(((attempt / combinations) as u64).checked_mul(0x1_0000)?)?;
    let mut bytes = i32::try_from(i128::from(seed) - i128::from(next))
        .ok()?
        .to_le_bytes();
    let mut choice = attempt % combinations;
    for (byte, constrained) in bytes.iter_mut().zip(mask) {
        if constrained {
            *byte = ILLEGAL[choice % ILLEGAL.len()];
            choice /= ILLEGAL.len();
        }
    }
    u64::try_from(i128::from(next) + i128::from(i32::from_le_bytes(bytes))).ok()
}

fn qualify_instruction(instruction: &iced_x86::Instruction) -> Result<(), Refusal> {
    use Mnemonic::*;
    // Deliberately explicit initial ABI envelope. Expanding it requires a
    // forced puzzle and independent state/fault evidence, not just decoding.
    if matches!(
        instruction.mnemonic(),
        Mov | Movzx
            | Movsx
            | Movsxd
            | Lea
            | Nop
            | Add
            | Adc
            | Sub
            | Sbb
            | And
            | Or
            | Xor
            | Cmp
            | Test
            | Inc
            | Dec
            | Neg
            | Not
            | Shl
            | Shr
            | Sar
            | Rol
            | Ror
            | Rcl
            | Rcr
            | Imul
            | Mul
            | Idiv
            | Div
            | Push
            | Pop
            | Pushfq
            | Ret
            | Jmp
            | Ja
            | Jae
            | Jb
            | Jbe
            | Je
            | Jne
            | Jg
            | Jge
            | Jl
            | Jle
            | Jo
            | Jno
            | Js
            | Jns
            | Jp
            | Jnp
            | Jrcxz
            | Loop
            | Loope
            | Loopne
    ) && !instruction.is_privileged()
        && !instruction.is_jmp_far_indirect()
        && (0..instruction.op_count()).all(|index| {
            instruction.op_kind(index) != iced_x86::OpKind::Register
                || instruction.op_register(index).is_gpr()
        })
        && !instruction.has_lock_prefix()
        && !instruction.has_rep_prefix()
        && !instruction.has_repne_prefix()
        && !matches!(
            instruction.op0_kind(),
            iced_x86::OpKind::FarBranch16 | iced_x86::OpKind::FarBranch32
        )
    {
        Ok(())
    } else {
        Err(Refusal::UnsupportedSemantics(format!(
            "{:?} has no qualified A1 relocation contract",
            instruction.mnemonic()
        )))
    }
}

#[allow(unused_unsafe)] // CPUID intrinsics are unsafe on the minimum supported Rust.
fn qualify_host() -> Result<(), Refusal> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // A1 freezes the legacy+EVEX decoder envelope. APX and MIC's MVEX are
        // not silently treated as the same encoding space.
        // SAFETY: CPUID is available in long mode.
        let leaf = unsafe { core::arch::x86_64::__cpuid_count(7, 1) };
        if leaf.edx & (1 << 21) != 0 {
            return Err(Refusal::UnsupportedSemantics("APX ISA profile".into()));
        }
        let cpu = unsafe { core::arch::x86_64::__cpuid(1) }.eax;
        let model = ((cpu >> 4) & 15) | ((cpu >> 12) & 0xf0);
        if ((cpu >> 8) & 15) == 6 && matches!(model, 0x57 | 0x85) {
            return Err(Refusal::UnsupportedSemantics("MVEX ISA profile".into()));
        }
        // Linux ARCH_SHSTK_STATUS. Unknown/unsupported kernels return EINVAL;
        // the unsafe embedding contract also excludes active CET/IBT.
        let mut status = 0_u64;
        let result = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005, &mut status) };
        if result == 0 && status != 0 {
            return Err(Refusal::UnsupportedSemantics(
                "active CET shadow stack".into(),
            ));
        }
        if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != 4096 {
            return Err(Refusal::UnsupportedSemantics("non-4KiB page size".into()));
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Err(Refusal::UnsupportedSemantics(
            "requires Linux x86-64".into(),
        ))
    }
}

fn occupied_ranges() -> Result<Vec<AddressRange>, Refusal> {
    let file =
        std::fs::File::open("/proc/self/maps").map_err(|e| Refusal::Backend(e.to_string()))?;
    let mut text = String::new();
    file.take(2 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|e| Refusal::Backend(e.to_string()))?;
    if text.len() > 2 * 1024 * 1024 {
        return Err(Refusal::AllocationUnavailable);
    }
    text.lines()
        .map(|line| {
            let addresses = line
                .split_whitespace()
                .next()
                .ok_or(Refusal::InvalidRange)?;
            let (start, end) = addresses.split_once('-').ok_or(Refusal::InvalidRange)?;
            let start = u64::from_str_radix(start, 16).map_err(|_| Refusal::InvalidRange)?;
            let end = u64::from_str_radix(end, 16).map_err(|_| Refusal::InvalidRange)?;
            let len = end.checked_sub(start).ok_or(Refusal::InvalidRange)?;
            AddressRange::new(
                start,
                usize::try_from(len).map_err(|_| Refusal::InvalidRange)?,
            )
        })
        .collect()
}

/// Binds a verified core plan to a caller-owned writable source alias.
pub struct LivePublisher<'a> {
    prepared: &'a PlannedInstall,
    writable_base: *mut u8,
}
impl<'a> LivePublisher<'a> {
    /// Creates a publisher without modifying source bytes.
    ///
    /// # Safety
    /// The pointer aliases the complete plan snapshot and remains valid through
    /// retirement. The embedding runtime owns all mappings, aliases, signals,
    /// continuations, and the no-CET System V execution envelope.
    pub unsafe fn new(prepared: &'a PlannedInstall, writable_base: *mut u8) -> Self {
        Self {
            prepared,
            writable_base,
        }
    }
}

// SAFETY: this implementation authenticates the original trusted plan, checks
// every read and lease, stages allocations/routes, and completes sync-core
// before issuing a receipt. Pointer validity is required at construction.
unsafe impl Publisher for LivePublisher<'_> {
    type Installed = InstalledOnce;
    fn publish_quiescent(
        &mut self,
        plan: &PatchPlan,
        lease: &mut QuiescenceLease<'_>,
    ) -> Result<(InstalledOnce, PublicationReceipt), PublicationFailure> {
        if plan != &self.prepared.plan {
            return Err(before(Refusal::InvalidPlan));
        }
        self.prepared
            .publish_inner(self.writable_base, lease, || Ok(()))
    }
}

impl PlannedInstall {
    /// Publishes with a caller-supplied final-permissions operation.
    ///
    /// The operation runs after stores and before sync-core/receipt. Its failure
    /// keeps the lease poisoned and all possibly reachable resources alive.
    ///
    /// # Safety
    /// Same mapping and exclusion contract as [`Self::publish`]. `finalize` must
    /// establish final executable permissions, must not admit execution or
    /// change bytes/identity, and must not panic or unwind.
    pub unsafe fn publish_with(
        &self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<(InstalledOnce, PublicationReceipt), PublicationFailure> {
        self.publish_inner(writable_base, lease, finalize)
    }

    fn publish_inner(
        &self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        mut finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<(InstalledOnce, PublicationReceipt), PublicationFailure> {
        lease.check(&self.plan).map_err(before)?;
        if writable_base.is_null() {
            return Err(before(Refusal::InvalidRange));
        }
        qualify_host().map_err(before)?;
        let current_state = crate::trampoline::SavedExtendedStateLayout::detect()
            .map_err(|error| before(Refusal::Backend(error.to_string())))?;
        if current_state != self.image.layout().saved_extended_state {
            return Err(before(Refusal::UnsupportedSemantics(
                "extended-state layout changed since planning".into(),
            )));
        }
        prepare_sync_core().map_err(before)?;
        let source = &self.plan.parts().reads[0];
        check_bytes(writable_base, &source.bytes).map_err(before)?;
        let reservation = crate::trap::reserve(
            self.plan.parts().physical_pc as usize,
            source.address as usize,
            source.address as usize + source.bytes.len(),
            0,
        )
        .map_err(|_| before(Refusal::OwnershipConflict))?;
        let staged = ExecutableTrampoline::allocate_image_at(&self.image, self.image.address())
            .map_err(|e| before(Refusal::Backend(e.to_string())))?;
        if staged.trampoline().address() != self.image.address() {
            return Err(before(Refusal::InvalidPlan));
        }
        let routes: Vec<_> = self
            .plan
            .parts()
            .obligations
            .iter()
            .filter_map(|obligation| {
                if let EntryObligation::Routed(route) = obligation {
                    Some(*route)
                } else {
                    None
                }
            })
            .collect();
        let mut routing = if routes.is_empty() {
            None
        } else {
            crate::entry_router::prepare().map_err(before)?;
            // SAFETY: staged code is initialized, dependency lease is held, and
            // routes are derived from the trusted emitter's exact entry map.
            Some(unsafe { crate::entry_router::stage(&routes) }.map_err(before)?)
        };
        // All allocation/signal setup precedes the final identity/byte check.
        lease.check(&self.plan).map_err(before)?;
        check_bytes(writable_base, &source.bytes).map_err(before)?;
        if routing.is_some() {
            crate::entry_router::verify().map_err(before)?;
        }
        let trampoline = staged.commit();
        trampoline.publish_program_counter_mappings();
        if let Some(registration) = routing.as_mut() {
            registration.commit();
        }
        let installed = InstalledOnce {
            plan: self.plan.clone(),
            writable_base,
            reservation: Some(reservation),
            routing,
            trampoline,
            retired: false,
        };
        lease.poison();
        for edit in &self.plan.parts().writes {
            let offset = (edit.address - source.address) as usize;
            // SAFETY: source ownership and complete read bounds were checked;
            // the constructor's writable-alias and lease contracts exclude all
            // concurrent accesses. There is no widened eight-byte store.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    edit.bytes.as_ptr(),
                    writable_base.add(offset),
                    edit.bytes.len(),
                );
            }
        }
        // Dropping the installed handle on error deliberately retains reachable
        // code, routing and byte ownership. The caller must keep the gate held.
        if let Err(reason) = finalize().and_then(|()| sync_core()) {
            return Err(PublicationFailure {
                reason,
                stage: FailureStage::KeepGated,
            });
        }
        lease.publication_completed();
        // SAFETY: every plan obligation, byte write, allocation and route is now
        // installed and instruction-stream visibility completed while held.
        let receipt = unsafe { PublicationReceipt::completed(self.plan.clone()) };
        Ok((installed, receipt))
    }
}

/// Permanently active interception; only generation retirement is exposed.
///
/// Drop preserves active code and routes. Explicit retirement requires a new
/// lease that also drains generated-code execution and saved contexts. Generated
/// code/reverse-PC metadata are retained for process lifetime in this first
/// implementation; retired source ownership and active SIGILL routes are released.
pub struct InstalledOnce {
    plan: PatchPlan,
    writable_base: *mut u8,
    reservation: Option<crate::trap::PendingTrapSite>,
    routing: Option<crate::entry_router::RouteRegistration>,
    trampoline: ExecutableTrampoline,
    retired: bool,
}
impl InstalledOnce {
    /// Exact installed plan and identity.
    pub const fn plan(&self) -> &PatchPlan {
        &self.plan
    }
    /// Generated mapping retained for the process lifetime.
    pub const fn trampoline(&self) -> &ExecutableTrampoline {
        &self.trampoline
    }
    /// Number of owned SIGILL entries actually routed.
    pub fn routed_entries(&self) -> u64 {
        self.routing.as_ref().map_or(0, |r| r.handled())
    }
    /// Whether source bytes were restored and routing disabled.
    pub const fn is_retired(&self) -> bool {
        self.retired
    }

    /// Restores original bytes under a fresh lease, with permissions already suitable.
    ///
    /// # Safety
    /// The retained source alias must be writable again. The lease must hold
    /// all source and generated ranges and drain every saved/executing reference.
    pub unsafe fn retire(
        &mut self,
        lease: &mut QuiescenceLease<'_>,
    ) -> Result<(), PublicationFailure> {
        self.retire_inner(lease, || Ok(()))
    }

    /// Retires and finalizes caller-owned source permissions before completion.
    ///
    /// # Safety
    /// The retained source alias must be writable again. `finalize` must
    /// restore final permissions without changing bytes/identity,
    /// admitting execution, or unwinding. The lease must cover all original and
    /// generated execution/saved references, as required by its constructor.
    pub unsafe fn retire_with(
        &mut self,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<(), PublicationFailure> {
        self.retire_inner(lease, finalize)
    }

    fn retire_inner(
        &mut self,
        lease: &mut QuiescenceLease<'_>,
        mut finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<(), PublicationFailure> {
        lease.check(&self.plan).map_err(before)?;
        if self.retired {
            return Ok(());
        }
        if !self
            .plan
            .parts()
            .allocations
            .iter()
            .all(|allocation| lease.covers(allocation.range))
        {
            return Err(before(Refusal::DependencyNotHeld));
        }
        if self.routing.is_some() {
            crate::entry_router::verify().map_err(before)?;
        }
        let source = &self.plan.parts().reads[0];
        let mut expected = source.bytes.clone();
        for edit in &self.plan.parts().writes {
            let offset = (edit.address - source.address) as usize;
            expected[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        check_bytes(self.writable_base, &expected).map_err(before)?;
        prepare_sync_core().map_err(before)?;
        lease.poison();
        for edit in &self.plan.parts().writes {
            let offset = (edit.address - source.address) as usize;
            // SAFETY: the live alias remains valid by construction, and the
            // retirement lease drains every reader/executor/saved continuation.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    source.bytes.as_ptr().add(offset),
                    self.writable_base.add(offset),
                    edit.bytes.len(),
                );
            }
        }
        if let Err(reason) = finalize().and_then(|()| sync_core()) {
            return Err(PublicationFailure {
                reason,
                stage: FailureStage::KeepGated,
            });
        }
        if let Some(routing) = &self.routing {
            routing.deactivate();
        }
        self.reservation.take();
        self.retired = true;
        lease.publication_completed();
        Ok(())
    }
}
impl Drop for InstalledOnce {
    fn drop(&mut self) {
        // An active permanent redirect outlives its Rust handle. Do not release
        // byte ownership merely because a caller drops the handle or an error.
        if let Some(reservation) = self.reservation.take() {
            std::mem::forget(reservation);
        }
    }
}

fn before(reason: Refusal) -> PublicationFailure {
    PublicationFailure {
        reason,
        stage: FailureStage::BeforeWrite,
    }
}
fn check_bytes(pointer: *mut u8, expected: &[u8]) -> Result<(), Refusal> {
    // SAFETY: only called with the source alias authenticated at the unsafe
    // constructor boundary and while the full read dependency is leased.
    let observed = unsafe { std::slice::from_raw_parts(pointer, expected.len()) };
    if observed == expected {
        Ok(())
    } else {
        Err(Refusal::ExpectedBytesChanged)
    }
}

fn prepare_sync_core() -> Result<(), Refusal> {
    const SYNC: libc::c_int = 1 << 5;
    const REGISTER: libc::c_int = 1 << 6;
    // SAFETY: Linux membarrier integer arguments, no pointers.
    let available = unsafe { libc::syscall(libc::SYS_membarrier, 0, 0, 0) };
    if available < 0
        || available & (SYNC | REGISTER) as libc::c_long != (SYNC | REGISTER) as libc::c_long
        || unsafe { libc::syscall(libc::SYS_membarrier, REGISTER, 0, 0) } != 0
    {
        return Err(Refusal::Synchronization);
    }
    Ok(())
}
fn sync_core() -> Result<(), Refusal> {
    // SAFETY: the command was queried and registered before any code write.
    if unsafe { libc::syscall(libc::SYS_membarrier, 1 << 5, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Synchronization)
    }
}
