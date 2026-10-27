//! Eager, generation-bound replacement of selected instructions with actual native outputs.
//!
//! Planning and publication allocate and use the ordinary core publisher. They
//! must finish under real exclusion before a lazy execution gate is armed.
//! No planner, allocator, publisher, or registry lookup runs in these callbacks.

use liteinst2::contracts::{
    AddressRange, CodeIdentity, FailureStage, LegalEntrySet, PatchPlan, PublicationFailure,
    PublicationReceipt, QuiescenceLease, Refusal,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, InstalledOnce, PlanMetrics, PlannedInstall, SearchPolicy,
    plan_install,
};
use liteinst2::trampoline::TrampolineImage;

mod callbacks;
mod encoding;
mod metrics;

pub use encoding::{SelectedDestination, SelectedInstruction, SelectedWidth, decode_selected};
pub use metrics::{SelectedClassCounters, selected_counters};

#[cfg(test)]
mod tests;

/// Exit status used when the closed syscall callback refuses an operation.
pub const REJECTED_SYSCALL_EXIT_STATUS: i32 = 126;

/// Selected class replaced by its native callback, independent of CPUID feature reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedKind {
    /// `0f a2`: actual CPUID using the saved low EAX and ECX inputs.
    Cpuid,
    /// `0f 31`: actual, unserialized RDTSC.
    Rdtsc,
    /// `0f 05`: the closed returning Linux read/write/getpid/gettid profile.
    Syscall,
    /// RDRAND with one 16-, 32- or 64-bit register result and architectural flags.
    Rdrand,
    /// RDSEED with one 16-, 32- or 64-bit register result and architectural flags.
    Rdseed,
    /// RDPID with one zero-extended TSC_AUX register result.
    Rdpid,
    /// RDTSCP with actual EDX:EAX timestamp and independent ECX TSC_AUX.
    Rdtscp,
}

impl SelectedKind {
    /// Canonical complete encoding for operand-free classes. Register-output
    /// encodings depend on their operand and therefore return `None`.
    /// `decode_selected` remains authoritative for the complete instruction.
    pub const fn encoding(self) -> Option<&'static [u8]> {
        match self {
            Self::Cpuid => Some(&[0x0f, 0xa2]),
            Self::Rdtsc => Some(&[0x0f, 0x31]),
            Self::Syscall => Some(&[0x0f, 0x05]),
            Self::Rdtscp => Some(&[0x0f, 0x01, 0xf9]),
            Self::Rdrand | Self::Rdseed | Self::Rdpid => None,
        }
    }

    const fn counter_index(self) -> usize {
        match self {
            Self::Cpuid => 0,
            Self::Rdtsc => 1,
            Self::Syscall => 2,
            Self::Rdrand => 3,
            Self::Rdseed => 4,
            Self::Rdpid => 5,
            Self::Rdtscp => 6,
        }
    }
}

/// Caller-certified source and entry facts for one selected site.
///
/// This API does not discover complete instruction heads, aliases, saved
/// continuations, or function boundaries. The core validates the supplied
/// certificate and refuses unresolved entries. Separate installs must not have
/// overlapping source snapshots; the core owns each complete snapshot range.
pub struct SelectedSite<'a> {
    /// Exact selected instruction class.
    pub kind: SelectedKind,
    /// Actual mapping incarnation and generation.
    pub identity: CodeIdentity,
    /// Immutable original snapshot, authenticated again during publication.
    pub code: &'a [u8],
    /// Executable address corresponding to the first snapshot byte.
    pub base_address: u64,
    /// Caller-certified containing function.
    pub function: AddressRange,
    /// Caller-certified containing basic block.
    pub block: AddressRange,
    /// Actual original instruction head, not a generated address.
    pub logical_pc: u64,
    /// Complete entry and resume facts for this exact generation.
    pub entries: &'a LegalEntrySet,
    /// Genuine placement and resource constraints passed unchanged to core.
    pub allocation: &'a AllocationPolicy,
    /// Tactic and search bounds passed unchanged to core.
    pub search: SearchPolicy,
}

/// Prepared core plan plus all buffers used for post-publication observations.
pub struct PreparedSelected {
    instruction: SelectedInstruction,
    core: PlannedInstall,
    expected_source: Vec<u8>,
    observed_source: Vec<u8>,
    observed_generated: Vec<u8>,
}

impl PreparedSelected {
    /// Plans a genuine ReplaceFirst callback without changing executable bytes.
    pub fn prepare(site: SelectedSite<'_>) -> Result<Self, Refusal> {
        let offset = site
            .logical_pc
            .checked_sub(site.base_address)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(Refusal::InvalidRange)?;
        let instruction = decode_selected(
            site.kind,
            site.logical_pc,
            site.code.get(offset..).ok_or(Refusal::InvalidRange)?,
        )?;
        let core = plan_install(&InstallRequest {
            identity: site.identity,
            code: site.code,
            base_address: site.base_address,
            function: site.function,
            block: site.block,
            logical_pc: site.logical_pc,
            entries: site.entries,
            hook: callbacks::for_instruction(&instruction)?,
            semantics: HookSemantics::ReplaceFirst,
            allocation: site.allocation,
            search: site.search,
        })?;
        let parts = core.plan().parts();
        // These are the actual single-image publisher's shape, not a fallback
        // that accepts an unobserved source or generated allocation.
        if parts.reads.len() != 1
            || parts.reads[0].address != site.base_address
            || parts.reads[0].bytes != site.code
            || parts.logical_pc != site.logical_pc
            || parts.generated.len() != 1
            || parts.generated[0].address != core.image().address()
            || parts.generated[0].bytes != core.image().bytes()
        {
            return Err(Refusal::InvalidPlan);
        }
        let mut expected_source = site.code.to_vec();
        for edit in &parts.writes {
            let start = edit
                .address
                .checked_sub(site.base_address)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(Refusal::InvalidPlan)?;
            let end = start
                .checked_add(edit.bytes.len())
                .ok_or(Refusal::InvalidPlan)?;
            expected_source
                .get_mut(start..end)
                .ok_or(Refusal::InvalidPlan)?
                .copy_from_slice(&edit.bytes);
        }
        let observed_source = vec![0; expected_source.len()];
        let observed_generated = vec![0; core.image().bytes().len()];
        Ok(Self {
            instruction,
            core,
            expected_source,
            observed_source,
            observed_generated,
        })
    }

    /// Exact original operation, length, prefixes and register operand.
    pub const fn instruction(&self) -> &SelectedInstruction {
        &self.instruction
    }

    /// Exact core plan, including actual tactic, dependencies and entry routes.
    pub fn plan(&self) -> &PatchPlan {
        self.core.plan()
    }

    /// Exact emitted image; this is still a plan until publication completes.
    pub fn image(&self) -> &TrampolineImage {
        self.core.image()
    }

    /// Actual bounded planner search evidence.
    pub fn metrics(&self) -> &PlanMetrics {
        self.core.metrics()
    }

    /// Publishes eagerly and observes the actual complete source and image.
    ///
    /// All observation buffers and the retaining owner are allocated before
    /// calling the core publisher. A post-write error retains the owner and
    /// poisons the lease; it must never be treated as permission to execute.
    ///
    /// # Safety
    /// `writable_base` aliases the entire source snapshot and remains valid for
    /// the installed lifetime. The lease must represent actual exclusion of
    /// execution, mutation, aliases and saved contexts, not a boolean assertion.
    /// `finalize` establishes readable RX permissions without admitting any
    /// execution, changing bytes/identity, panicking or unwinding. All core
    /// no-CET/System-V/XSAVE/signal and writable-stack obligations apply.
    /// Execution must also meet the closed callback contract in CONTRACT.md:
    /// no application signals, signal returns, TLS/mapping/lifecycle changes,
    /// or syscall buffers overlapping runtime/code/saved-state storage.
    /// Kernel policy must not distinguish the original syscall PC/RSP from
    /// this callback's PC/RSP or other instrumentation context (for example,
    /// IP-sensitive seccomp or syscall-user-dispatch regions). Address-insensitive
    /// policy is not excluded; no runtime policy equivalence is inferred.
    /// Address-sensitive tracing/audit observations are not transparent original
    /// context evidence. Raw supported-syscall errors are forwarded unchanged.
    pub unsafe fn publish_with(
        self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<Box<InstalledSelected>, SelectedPublicationFailure> {
        let mut retained = Box::new(InstalledSelected {
            prepared: self,
            installed: None,
            receipt: None,
            captured: false,
            verified: false,
        });
        // SAFETY: the caller supplies the core's complete mapping/exclusion
        // contract and non-unwinding finalizer. No execution is admitted here.
        let result = unsafe {
            retained
                .prepared
                .core
                .publish_with(writable_base, lease, finalize)
        };
        let (installed, receipt) = match result {
            Ok(result) => result,
            Err(failure) => return Err(SelectedPublicationFailure { failure, retained }),
        };
        // Install the genuine returned owners before any additional check.
        retained.installed = Some(installed);
        retained.receipt = Some(receipt);
        // SAFETY: the original alias is still readable under the held lease;
        // the returned core owner retains its readable executable image.
        let checked = unsafe { retained.capture_and_check(writable_base) };
        if let Err(reason) = checked {
            lease.poison();
            return Err(SelectedPublicationFailure {
                failure: PublicationFailure {
                    reason,
                    stage: FailureStage::KeepGated,
                },
                retained,
            });
        }
        retained.verified = true;
        Ok(retained)
    }
}

/// Genuine publication owners and retained actual byte observations.
///
/// Retain this owner and the original mapping until the gate has disarmed and
/// all execution/saved references are excluded. Core install-once Drop keeps
/// reachable generated code/routes alive; dropping this is not retirement.
pub struct InstalledSelected {
    prepared: PreparedSelected,
    installed: Option<InstalledOnce>,
    receipt: Option<PublicationReceipt>,
    captured: bool,
    verified: bool,
}

impl InstalledSelected {
    /// Selected instruction class.
    pub const fn kind(&self) -> SelectedKind {
        self.prepared.instruction.kind()
    }

    /// Exact original operation, including its actual logical instruction head.
    pub const fn instruction(&self) -> &SelectedInstruction {
        self.prepared.instruction()
    }

    /// Exact core source/generated-byte plan.
    pub fn plan(&self) -> &PatchPlan {
        self.prepared.plan()
    }

    /// Genuine core owner, present only if the core publisher returned it.
    pub fn installed(&self) -> Option<&InstalledOnce> {
        self.installed.as_ref()
    }

    /// Genuine receipt returned by the core publisher, never reconstructed.
    pub fn receipt(&self) -> Option<&PublicationReceipt> {
        self.receipt.as_ref()
    }

    /// Whether both complete actual observations matched the returned plan.
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// Actual complete post-publication source bytes, including unchanged bytes.
    pub fn observed_source(&self) -> Option<&[u8]> {
        self.captured
            .then_some(self.prepared.observed_source.as_slice())
    }

    /// Actual emitted executable bytes read from the retained core mapping.
    pub fn observed_generated(&self) -> Option<&[u8]> {
        self.captured
            .then_some(self.prepared.observed_generated.as_slice())
    }

    unsafe fn capture_and_check(&mut self, source: *const u8) -> Result<(), Refusal> {
        let installed = self.installed.as_ref().ok_or(Refusal::InvalidPlan)?;
        let receipt = self.receipt.as_ref().ok_or(Refusal::InvalidPlan)?;
        if installed.plan() != self.prepared.plan()
            || receipt.plan() != self.prepared.plan()
            || installed.trampoline().address() != self.prepared.image().address()
            || installed.trampoline().code_len() != self.prepared.observed_generated.len()
        {
            return Err(Refusal::InvalidPlan);
        }
        // SAFETY: caller holds the original live alias and genuine core image;
        // both preallocated output Vecs are separate owned allocations.
        unsafe {
            std::ptr::copy_nonoverlapping(
                source,
                self.prepared.observed_source.as_mut_ptr(),
                self.prepared.observed_source.len(),
            );
            std::ptr::copy_nonoverlapping(
                installed.trampoline().address() as *const u8,
                self.prepared.observed_generated.as_mut_ptr(),
                self.prepared.observed_generated.len(),
            );
        }
        self.captured = true;
        if self.prepared.observed_source != self.prepared.expected_source
            || self.prepared.observed_generated != self.prepared.image().bytes()
        {
            return Err(Refusal::ExpectedBytesChanged);
        }
        Ok(())
    }
}

/// Publication failure retaining the prepared and any returned installed owner.
pub struct SelectedPublicationFailure {
    /// Exact core failure or an additional actual-byte verification failure.
    pub failure: PublicationFailure,
    /// Retained evidence and genuine core owners, including failed prefixes.
    pub retained: Box<InstalledSelected>,
}

impl std::fmt::Debug for SelectedPublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedPublicationFailure")
            .field("failure", &self.failure)
            .field("kind", &self.retained.kind())
            .field("verified", &self.retained.verified())
            .finish()
    }
}

impl std::fmt::Display for SelectedPublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "selected publication {:?}: {}",
            self.failure.stage, self.failure.reason
        )
    }
}

impl std::error::Error for SelectedPublicationFailure {}
