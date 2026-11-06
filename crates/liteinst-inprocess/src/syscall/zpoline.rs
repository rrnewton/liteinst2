//! One certified eager x86-64 zpoline site.
//!
//! A proven native `syscall` (`0f 05`) is replaced in place by the
//! same-length `call *%rax` (`ff d0`). For every admitted canonical syscall
//! number, that call lands in a one-page NOP sled at virtual address zero.
//! The sled restores the pre-call stack pointer with `lea` and jumps to the
//! core exact-syscall trampoline; the trampoline's callback authenticates the
//! call return slot left in the red zone before delegating to the existing
//! selected-syscall forwarding callback.
//!
//! This is deliberately one certified site, not a census, lazypoline, or
//! whole-program mechanism. Mapping virtual address zero is a run-level
//! prerequisite and is reported as a named environment refusal when denied.

use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use liteinst::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, FailureStage, LegalEntrySet, QuiescenceLease,
    Refusal, ResumeObligation,
};
use liteinst::scanner::{InstructionScanner, ScanError};
use liteinst::sync_core::{SyncCore, SyncCoreError};
use liteinst::trampoline::{
    ExecutableTrampoline, HookCallback, HookContext, TrampolineError, TrampolinePlan,
};
use liteinst::x86::OpKind;

use crate::selected::{
    REJECTED_SYSCALL_EXIT_STATUS, SelectedInstruction, SelectedKind, decode_selected,
    syscall_callback,
};
use crate::syscall::{
    SyscallRefusal, SyscallStrategy, SyscallStrategyConfig, first_profile_supports,
};

const ORIGINAL_SYSCALL: [u8; 2] = [0x0f, 0x05];
const ZPOLINE_CALL_RAX: [u8; 2] = [0xff, 0xd0];
const COMMON_STUB_LEN: usize = 19;
const OWNER_EMPTY: u8 = 0;
const OWNER_INSTALLING: u8 = 1;
const OWNER_INSTALLED: u8 = 2;
const OWNER_POISONED: u8 = 3;

static ZPOLINE_OWNER: AtomicU8 = AtomicU8::new(OWNER_EMPTY);
static ZPOLINE_EXPECTED_SITE: AtomicU64 = AtomicU64::new(0);
static ZPOLINE_EXPECTED_RETURN: AtomicU64 = AtomicU64::new(0);
static ZPOLINE_EXPECTED_NR: AtomicU32 = AtomicU32::new(0);
static ZPOLINE_DELEGATE: AtomicUsize = AtomicUsize::new(0);

/// Exact low-page sled geometry for one validated config and host page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZpolineSledLayout {
    page_size: usize,
    max_syscall_nr: u32,
    common_entry: usize,
}

impl ZpolineSledLayout {
    /// Size of the single sled page.
    pub const fn page_size(self) -> usize {
        self.page_size
    }

    /// Inclusive largest syscall number that lands in the NOP sled.
    pub const fn max_syscall_nr(self) -> u32 {
        self.max_syscall_nr
    }

    /// Offset of the stack-adjusting common stub within virtual page zero.
    pub const fn common_entry(self) -> usize {
        self.common_entry
    }

    fn new(page_size: usize, max_syscall_nr: u32) -> Result<Self, SyscallRefusal> {
        if !page_size.is_power_of_two() || page_size < 4096 {
            return Err(SyscallRefusal::InvalidConfig {
                field: "page_size",
                reason: "must be a power of two and at least 4096",
            });
        }
        let first_stub_offset =
            (max_syscall_nr as usize)
                .checked_add(1)
                .ok_or(SyscallRefusal::InvalidConfig {
                    field: "max_syscall_nr",
                    reason: "common-entry offset overflows",
                })?;
        let common_entry = first_stub_offset.next_multiple_of(16);
        if common_entry
            .checked_add(COMMON_STUB_LEN)
            .is_none_or(|end| end > page_size)
        {
            return Err(SyscallRefusal::InvalidConfig {
                field: "max_syscall_nr",
                reason: "sled common stub does not fit in one host page",
            });
        }
        Ok(Self {
            page_size,
            max_syscall_nr,
            common_entry,
        })
    }

    fn build(self, handler: u64) -> Vec<u8> {
        let mut sled = vec![0x90; self.page_size];
        let stub = &mut sled[self.common_entry..self.common_entry + COMMON_STUB_LEN];
        // lea rsp, [rsp+8]; jmp qword ptr [rip+0]; handler address.
        stub[0..5].copy_from_slice(&[0x48, 0x8d, 0x64, 0x24, 0x08]);
        stub[5..11].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
        stub[11..19].copy_from_slice(&handler.to_le_bytes());
        sled
    }
}

fn host_page_size() -> Result<usize, SyscallRefusal> {
    // SAFETY: sysconf with the page-size name has no pointer arguments.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = usize::try_from(value).map_err(|_| SyscallRefusal::AllocationUnavailable)?;
    ZpolineSledLayout::new(page_size, 0).map(|_| page_size)
}

struct SledMapping {
    fd: c_int,
    writable: *mut u8,
    executable: *mut u8,
    executable_mapped: bool,
    len: usize,
    committed: bool,
}

impl SledMapping {
    fn probe_and_map(len: usize) -> Result<Self, SyscallRefusal> {
        const NAME: &[u8] = b"liteinst-zpoline-sled\0";
        // SAFETY: the name is NUL-terminated and memfd creation returns either
        // a new owned descriptor or -1 with errno.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                NAME.as_ptr(),
                libc::MFD_CLOEXEC | 0x0002,
            )
        };
        if fd < 0 || fd > i64::from(c_int::MAX) {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        let fd = fd as c_int;
        let mut mapping = Self {
            fd,
            writable: std::ptr::null_mut(),
            executable: std::ptr::null_mut(),
            executable_mapped: false,
            len,
            committed: false,
        };
        // SAFETY: fd is the owned memfd created above.
        if unsafe { libc::ftruncate(fd, len as libc::off_t) } != 0 {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        // SAFETY: a fresh shared writable alias of the sized owned memfd.
        let writable = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if writable == libc::MAP_FAILED {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        mapping.writable = writable.cast::<u8>();

        // SAFETY: MAP_FIXED_NOREPLACE asks for exactly VA 0 and cannot replace
        // an existing mapping on supported kernels.
        let executable = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                fd,
                0,
            )
        };
        if executable == libc::MAP_FAILED {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(if errno == libc::EEXIST {
                SyscallRefusal::LowPageOccupied
            } else {
                SyscallRefusal::LowPageUnavailable { errno }
            });
        }
        if !executable.is_null() {
            // An old kernel ignoring NOREPLACE could relocate or replace; do
            // not retain a mapping anywhere except exactly VA 0.
            // SAFETY: executable is the mapping just returned.
            unsafe { libc::munmap(executable, len) };
            return Err(SyscallRefusal::LowPageUnavailable {
                errno: libc::EADDRNOTAVAIL,
            });
        }
        mapping.executable = executable.cast::<u8>();
        mapping.executable_mapped = true;
        Ok(mapping)
    }

    fn publish_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, SyscallRefusal> {
        if bytes.len() != self.len || self.writable.is_null() || self.committed {
            return Err(SyscallRefusal::AllocationUnavailable);
        }
        // SAFETY: both aliases cover exactly len bytes from the owned memfd.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.writable, bytes.len());
        }
        let observed = self.observed();
        if observed != bytes {
            return Err(SyscallRefusal::ExpectedBytesChanged);
        }
        // SAFETY: the writable alias is still the mapping created above.
        if unsafe { libc::munmap(self.writable.cast::<c_void>(), self.len) } != 0 {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        self.writable = std::ptr::null_mut();
        let seals = libc::F_SEAL_WRITE
            | libc::F_SEAL_FUTURE_WRITE
            | libc::F_SEAL_SHRINK
            | libc::F_SEAL_GROW
            | libc::F_SEAL_SEAL;
        // SAFETY: fd remains the owned memfd and no writable alias remains.
        if unsafe { libc::fcntl(self.fd, libc::F_ADD_SEALS, seals) } != 0 {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        // SAFETY: querying seals does not mutate the mapping.
        let observed_seals = unsafe { libc::fcntl(self.fd, libc::F_GET_SEALS) };
        if observed_seals < 0 || observed_seals & seals != seals {
            return Err(SyscallRefusal::MemfdDualMapFailed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        // SAFETY: the executable alias retains the backing after descriptor close.
        unsafe { libc::close(self.fd) };
        self.fd = -1;
        if self.observed() != bytes {
            return Err(SyscallRefusal::ExpectedBytesChanged);
        }
        Ok(observed)
    }

    fn observed(&self) -> Vec<u8> {
        let mut observed = vec![0; self.len];
        // SAFETY: executable alias is readable for exactly len bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(self.executable, observed.as_mut_ptr(), self.len);
        }
        observed
    }

    fn unmap(&mut self) -> Result<(), SyscallRefusal> {
        let mut result = Ok(());
        if !self.writable.is_null() {
            // SAFETY: writable is still this mapping's owned alias.
            if unsafe { libc::munmap(self.writable.cast::<c_void>(), self.len) } != 0 {
                result = Err(SyscallRefusal::MemfdDualMapFailed {
                    errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                });
            } else {
                self.writable = std::ptr::null_mut();
            }
        }
        if self.executable_mapped {
            // SAFETY: executable is exactly address zero for len bytes. The
            // separate boolean distinguishes it from an absent mapping.
            if unsafe { libc::munmap(self.executable.cast::<c_void>(), self.len) } != 0 {
                result = Err(SyscallRefusal::MemfdDualMapFailed {
                    errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                });
            } else {
                self.executable_mapped = false;
            }
        }
        if self.fd >= 0 {
            // SAFETY: fd is still owned here.
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
        result
    }

    fn commit(mut self) -> Self {
        self.committed = true;
        self
    }
}

impl Drop for SledMapping {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.unmap();
        }
    }
}

fn qualify_host() -> Result<usize, SyscallRefusal> {
    let page_size = host_page_size()?;
    let leaf = core::arch::x86_64::__cpuid_count(7, 1);
    if leaf.edx & (1 << 21) != 0 {
        return Err(SyscallRefusal::StrategyUnavailableOnArch);
    }
    let cpu = core::arch::x86_64::__cpuid(1).eax;
    let model = ((cpu >> 4) & 15) | ((cpu >> 12) & 0xf0);
    if ((cpu >> 8) & 15) == 6 && matches!(model, 0x57 | 0x85) {
        return Err(SyscallRefusal::StrategyUnavailableOnArch);
    }
    // Linux ARCH_SHSTK_STATUS. Unsupported kernels return an error; any
    // successful nonzero feature word is outside this no-CET profile.
    let mut status = 0_u64;
    // SAFETY: status points to one writable u64 for the arch_prctl query.
    let result = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005, &mut status) };
    if result == 0 && status != 0 {
        return Err(SyscallRefusal::CetUnsupported);
    }
    Ok(page_size)
}

unsafe fn refuse_hook() -> ! {
    // SAFETY: this is the selected callback's fail-closed process exit. The
    // generated trampoline context is abandoned and no Rust state is reused.
    unsafe {
        core::arch::asm!(
            "syscall",
            "ud2",
            in("rax") libc::SYS_exit_group as u64,
            in("rdi") REJECTED_SYSCALL_EXIT_STATUS as u64,
            options(noreturn, nostack)
        );
    }
}

unsafe extern "C" fn zpoline_hook(context: *mut HookContext) {
    // SAFETY: the exact trampoline passes one live HookContext. The sled has
    // restored the original RSP; the zpoline call return remains at RSP-8 in
    // the untouched red zone for authentication here.
    let context = unsafe { &mut *context };
    let expected_site = ZPOLINE_EXPECTED_SITE.load(Ordering::Acquire);
    let expected_return = ZPOLINE_EXPECTED_RETURN.load(Ordering::Acquire);
    let expected_nr = ZPOLINE_EXPECTED_NR.load(Ordering::Acquire);
    let delegate_bits = ZPOLINE_DELEGATE.load(Ordering::Acquire);
    let Some(return_slot) = context.stack_pointer.checked_sub(8) else {
        // SAFETY: authentication failed before any genuine syscall.
        unsafe { refuse_hook() }
    };
    // SAFETY: the publish contract keeps the original red-zone word readable
    // and the exact trampoline does not overwrite it.
    let observed_return = unsafe { std::ptr::read_volatile(return_slot as *const u64) };
    if context.instruction_pointer != expected_site
        || context.rax != u64::from(expected_nr)
        || observed_return != expected_return
        || delegate_bits == 0
    {
        // SAFETY: unauthenticated sled entry is refused before forwarding.
        unsafe { refuse_hook() }
    }
    // SAFETY: publish stores the selected callback address before patching
    // the only admitted source route to this wrapper.
    let delegate: HookCallback = unsafe { core::mem::transmute(delegate_bits) };
    // SAFETY: context remains the live trampoline context for this call.
    unsafe { delegate(context) }
}

fn claim_owner() -> Result<(), SyscallRefusal> {
    match ZPOLINE_OWNER.compare_exchange(
        OWNER_EMPTY,
        OWNER_INSTALLING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => Ok(()),
        Err(OWNER_INSTALLED) => Err(SyscallRefusal::StrategyAlreadyInstalled),
        Err(OWNER_POISONED) => Err(SyscallRefusal::PublicationPoisoned),
        Err(_) => Err(SyscallRefusal::ConflictingStrategyInstalled),
    }
}

fn release_owner() {
    let _ = ZPOLINE_OWNER.compare_exchange(
        OWNER_INSTALLING,
        OWNER_EMPTY,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

fn core_refusal(error: Refusal) -> SyscallRefusal {
    match error {
        Refusal::NotInstructionHead => SyscallRefusal::NotInstructionHead,
        Refusal::ExpectedBytesChanged => SyscallRefusal::ExpectedBytesChanged,
        Refusal::StaleGeneration => SyscallRefusal::StaleGeneration,
        Refusal::DependencyNotHeld => SyscallRefusal::DependencyNotHeld,
        Refusal::OwnershipConflict => SyscallRefusal::OwnershipConflict,
        Refusal::AllocationUnavailable => SyscallRefusal::AllocationUnavailable,
        Refusal::SignalContract => SyscallRefusal::SignalContract,
        Refusal::Synchronization => SyscallRefusal::SynchronizationFailed,
        Refusal::InvalidRange | Refusal::InvalidPlan => SyscallRefusal::InvalidConfig {
            field: "site",
            reason: "core rejected the certified site or plan",
        },
        Refusal::UnsupportedSemantics(_) => SyscallRefusal::NotSyscallSite,
        _ => SyscallRefusal::StrategyUnavailableOnBackend,
    }
}

fn trampoline_refusal(error: TrampolineError) -> SyscallRefusal {
    match error {
        TrampolineError::SiteNotFound { .. } => SyscallRefusal::NotInstructionHead,
        TrampolineError::NotExactSyscall { .. } => SyscallRefusal::NotSyscallSite,
        TrampolineError::BackingStore { .. }
        | TrampolineError::ProcessMaps { .. }
        | TrampolineError::NoReachableMapping
        | TrampolineError::ExactAddressUnavailable { .. }
        | TrampolineError::ArenaFull
        | TrampolineError::CodeTooLarge { .. }
        | TrampolineError::InvalidPageSize => SyscallRefusal::AllocationUnavailable,
        TrampolineError::UnsupportedPlatform => SyscallRefusal::StrategyUnavailableOnArch,
        TrampolineError::ReturnAddressOverflow { .. }
        | TrampolineError::AddressNotRepresentable { .. } => SyscallRefusal::InvalidConfig {
            field: "logical_pc",
            reason: "address or return address is not representable",
        },
        _ => SyscallRefusal::StrategyUnavailableOnBackend,
    }
}

fn scan_refusal(error: ScanError) -> SyscallRefusal {
    match error {
        ScanError::InvalidInstruction { .. } => SyscallRefusal::NotInstructionHead,
        ScanError::AddressRangeOverflow { .. } | ScanError::AddressNotRepresentable { .. } => {
            SyscallRefusal::InvalidConfig {
                field: "code",
                reason: "snapshot address range is not representable",
            }
        }
        ScanError::PrefixTooShort { .. } | ScanError::UnsupportedCacheLineGeometry { .. } => {
            SyscallRefusal::InvalidConfig {
                field: "code",
                reason: "snapshot scan geometry is unsupported",
            }
        }
    }
}

/// Caller-certified facts for the one eager zpoline site in this slice.
///
/// `syscall_nr` certifies that every execution reaching `logical_pc` holds
/// that exact canonical, zero-extended syscall number in RAX. A generic
/// dynamic syscall wrapper therefore needs a stronger future certificate and
/// is not admitted by merely naming one observed number as a guess.
pub struct ZpolineSite<'a> {
    /// Frozen strategy selection; its strategy must be `Zpoline`.
    pub config: SyscallStrategyConfig,
    /// Actual mapping incarnation and generation.
    pub identity: CodeIdentity,
    /// Immutable original snapshot, authenticated again during publication.
    pub code: &'a [u8],
    /// Executable address corresponding to the first snapshot byte.
    pub base_address: u64,
    /// Actual native `syscall` instruction head.
    pub logical_pc: u64,
    /// Complete entry and resume facts for this exact generation.
    pub entries: &'a LegalEntrySet,
    /// Exact canonical syscall number certified for every execution.
    pub syscall_nr: u32,
}

/// Exact handler plan and source/sled facts for one certified zpoline site.
/// Preparation maps and patches nothing.
pub struct PreparedZpoline {
    config: SyscallStrategyConfig,
    instruction: SelectedInstruction,
    identity: CodeIdentity,
    base_address: u64,
    logical_pc: u64,
    return_pc: u64,
    syscall_nr: u32,
    source: Vec<u8>,
    expected_source: Vec<u8>,
    plan: TrampolinePlan,
    delegate: HookCallback,
    sled_layout: ZpolineSledLayout,
}

impl PreparedZpoline {
    /// Validates the certified site and builds the exact-syscall handler plan.
    pub fn prepare(site: ZpolineSite<'_>) -> Result<Self, SyscallRefusal> {
        site.config.validate()?;
        if site.config.strategy() != SyscallStrategy::Zpoline {
            return Err(SyscallRefusal::InvalidConfig {
                field: "strategy",
                reason: "zpoline site requires the zpoline strategy",
            });
        }
        if site.syscall_nr > site.config.max_syscall_nr() {
            return Err(SyscallRefusal::SyscallNumberRangeUnproven);
        }
        if !first_profile_supports(site.syscall_nr) {
            return Err(SyscallRefusal::UnsupportedSyscallSemantics {
                nr: site.syscall_nr,
            });
        }
        let page_size = qualify_host()?;
        let sled_layout = ZpolineSledLayout::new(page_size, site.config.max_syscall_nr())?;

        let source_range =
            AddressRange::new(site.base_address, site.code.len()).map_err(core_refusal)?;
        if site.entries.identity != site.identity || !site.entries.scope.covers(source_range) {
            return Err(SyscallRefusal::DependencyNotHeld);
        }
        if site.entries.completeness == EntryCompleteness::Incomplete
            || matches!(site.entries.resumes, ResumeObligation::Unresolved)
        {
            return Err(SyscallRefusal::DependencyNotHeld);
        }
        let return_pc = site
            .logical_pc
            .checked_add(2)
            .ok_or(SyscallRefusal::InvalidConfig {
                field: "logical_pc",
                reason: "return address overflows",
            })?;
        if site.entries.entries.iter().any(|entry| {
            entry.address == site.logical_pc + 1
                || entry.requires_endbr && entry.address == site.logical_pc
        }) {
            return Err(SyscallRefusal::InteriorBranchTarget);
        }
        if let ResumeObligation::Enumerated(addresses) = &site.entries.resumes
            && addresses.contains(&(site.logical_pc + 1))
        {
            return Err(SyscallRefusal::InteriorBranchTarget);
        }
        if site.entries.completeness == EntryCompleteness::Complete
            && !site
                .entries
                .entries
                .iter()
                .any(|entry| entry.address == site.logical_pc)
        {
            return Err(SyscallRefusal::NotInstructionHead);
        }

        let offset = site
            .logical_pc
            .checked_sub(site.base_address)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(SyscallRefusal::InvalidConfig {
                field: "logical_pc",
                reason: "site is outside the snapshot",
            })?;
        let site_bytes = site
            .code
            .get(offset..offset + 2)
            .ok_or(SyscallRefusal::NotSyscallSite)?;
        if site_bytes != ORIGINAL_SYSCALL {
            let decoded = liteinst::x86::decode64(
                site.logical_pc,
                site.code.get(offset..).unwrap_or_default(),
            );
            return Err(match liteinst::x86::selected_code(&decoded.instruction) {
                Some(
                    liteinst::x86::SelectedClass::Sysenter | liteinst::x86::SelectedClass::Int80,
                ) => SyscallRefusal::UnsupportedSyscallEntry,
                _ => SyscallRefusal::NotSyscallSite,
            });
        }
        let instruction = decode_selected(
            SelectedKind::Syscall,
            site.logical_pc,
            site.code
                .get(offset..)
                .ok_or(SyscallRefusal::InvalidConfig {
                    field: "logical_pc",
                    reason: "site is outside the snapshot",
                })?,
        )
        .map_err(core_refusal)?;
        let delegate = syscall_callback(&instruction).map_err(core_refusal)?;

        let scan = InstructionScanner::default()
            .scan(site.code, site.base_address)
            .map_err(scan_refusal)?;
        if scan.site(site.logical_pc).is_none() {
            return Err(SyscallRefusal::NotInstructionHead);
        }
        if scan.instructions().iter().any(|scanned| {
            let instruction = scanned.instruction();
            instruction.op0_kind() == OpKind::NearBranch64
                && instruction.near_branch_target() == site.logical_pc + 1
        }) {
            return Err(SyscallRefusal::InteriorBranchTarget);
        }

        let plan =
            TrampolinePlan::from_scan_replacing_exact_syscall(&scan, site.logical_pc, zpoline_hook)
                .map_err(trampoline_refusal)?;
        let source = site.code.to_vec();
        let mut expected_source = source.clone();
        expected_source[offset..offset + 2].copy_from_slice(&ZPOLINE_CALL_RAX);

        Ok(Self {
            config: site.config,
            instruction,
            identity: site.identity,
            base_address: site.base_address,
            logical_pc: site.logical_pc,
            return_pc,
            syscall_nr: site.syscall_nr,
            source,
            expected_source,
            plan,
            delegate,
            sled_layout,
        })
    }

    /// Frozen strategy config used by this plan.
    pub const fn config(&self) -> SyscallStrategyConfig {
        self.config
    }

    /// Exact decoded selected syscall instruction.
    pub const fn instruction(&self) -> &SelectedInstruction {
        &self.instruction
    }

    /// Exact handler trampoline plan; this is not installed yet.
    pub fn plan(&self) -> &TrampolinePlan {
        &self.plan
    }

    /// Exact sled geometry derived from the config and host page size.
    pub const fn sled_layout(&self) -> ZpolineSledLayout {
        self.sled_layout
    }

    /// Builds the complete sled image for an allocated handler address.
    pub fn sled_image(&self, handler: u64) -> Vec<u8> {
        self.sled_layout.build(handler)
    }

    fn source_range(&self) -> Result<AddressRange, SyscallRefusal> {
        AddressRange::new(self.base_address, self.source.len()).map_err(core_refusal)
    }

    fn offset(&self) -> usize {
        usize::try_from(self.logical_pc - self.base_address)
            .expect("prepared zpoline offset was checked during preparation")
    }
}

fn sync_refusal(error: SyncCoreError) -> SyscallRefusal {
    match error {
        SyncCoreError::MissingCapability { .. } | SyncCoreError::UnsupportedPlatform => {
            SyscallRefusal::SyncCoreUnavailable
        }
        SyncCoreError::SystemCall { .. }
        | SyncCoreError::UnexpectedResult { .. }
        | SyncCoreError::DifferentProcess { .. } => SyscallRefusal::SynchronizationFailed,
    }
}

unsafe fn read_live(source: *const u8, out: &mut [u8]) {
    // SAFETY: callers hold the lease and guarantee source aliases out.len()
    // readable bytes for this copy.
    unsafe { std::ptr::copy_nonoverlapping(source, out.as_mut_ptr(), out.len()) }
}

unsafe fn write_site_word(address: *mut u8, bytes: [u8; 2]) {
    let value = u16::from_le_bytes(bytes);
    // SAFETY: callers hold the publication lease, provide a writable alias
    // for both bytes, and synchronize instruction fetch before admission.
    unsafe {
        core::arch::asm!(
            "mov word ptr [{address}], {value:x}",
            address = in(reg) address,
            value = in(reg) value,
            options(nostack)
        );
    }
}

fn clear_hook_state() {
    ZPOLINE_DELEGATE.store(0, Ordering::Release);
    ZPOLINE_EXPECTED_RETURN.store(0, Ordering::Release);
    ZPOLINE_EXPECTED_SITE.store(0, Ordering::Release);
    ZPOLINE_EXPECTED_NR.store(0, Ordering::Release);
}

/// Exact zpoline publication failure, retaining the strategy-level name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZpolineFailure {
    /// Named strategy refusal.
    pub reason: SyscallRefusal,
    /// Whether the failure happened before any source write or whether the
    /// lease must remain gated after one was attempted.
    pub stage: FailureStage,
}

/// Publication or retirement failure retaining all genuine owners.
pub struct ZpolinePublicationFailure {
    /// Exact named failure and stage.
    pub failure: ZpolineFailure,
    /// Prepared plan, handler/sled owners, and observations, including failed
    /// prefixes. Dropping an uncommitted sled owner unmaps its low page.
    pub retained: Box<InstalledZpoline>,
}

impl std::fmt::Debug for ZpolinePublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZpolinePublicationFailure")
            .field("failure", &self.failure)
            .field("logical_pc", &self.retained.prepared.logical_pc)
            .field("verified", &self.retained.verified())
            .finish()
    }
}

impl std::fmt::Display for ZpolinePublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "zpoline publication {:?}: {}",
            self.failure.stage, self.failure.reason
        )
    }
}

impl std::error::Error for ZpolinePublicationFailure {}

/// Process-lifetime owner for one installed zpoline site and its sled.
///
/// Retain this owner until `retire` succeeds under a fresh lease. Dropping a
/// verified owner intentionally does not unmap reachable handler or sled code.
pub struct InstalledZpoline {
    prepared: PreparedZpoline,
    trampoline: Option<ExecutableTrampoline>,
    sled: Option<SledMapping>,
    observed_source: Vec<u8>,
    observed_handler: Vec<u8>,
    observed_sled: Vec<u8>,
    captured: bool,
    verified: bool,
    write_attempted: bool,
}

impl InstalledZpoline {
    /// Prepared plan retained with the genuine owners.
    pub const fn prepared(&self) -> &PreparedZpoline {
        &self.prepared
    }

    /// Allocated handler trampoline address, when allocation was reached.
    pub fn handler_address(&self) -> Option<u64> {
        self.trampoline
            .as_ref()
            .map(|trampoline| trampoline.address())
    }

    /// Whether source, handler, and sled observations all matched.
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// Actual complete source bytes after the latest captured state.
    pub fn observed_source(&self) -> Option<&[u8]> {
        self.captured.then_some(self.observed_source.as_slice())
    }

    /// Actual handler bytes read from the executable mapping.
    pub fn observed_handler(&self) -> Option<&[u8]> {
        self.captured.then_some(self.observed_handler.as_slice())
    }

    /// Actual sled bytes read through the executable VA-zero alias.
    pub fn observed_sled(&self) -> Option<&[u8]> {
        self.captured.then_some(self.observed_sled.as_slice())
    }
}

impl PreparedZpoline {
    /// Allocates the low sled and exact handler, publishes `ff d0`, and
    /// verifies all three actual images before returning their owner.
    ///
    /// # Safety
    /// `writable_base` aliases the entire prepared snapshot and remains valid
    /// for the installed lifetime. The lease must represent actual exclusion
    /// of execution, mutation, aliases, threads/signals that can observe the
    /// temporary sled/handler state, and saved continuations. `finalize`
    /// establishes final readable/RX permissions without admitting execution,
    /// changing bytes/identity, panicking, or unwinding.
    ///
    /// The certified site must execute with a writable System V stack below
    /// its red zone satisfying the core exact trampoline, no active CET, no
    /// application signal delivery in generated code, no recursion or
    /// nonlocal exit through the callback, and no syscall buffers overlapping
    /// source/runtime/saved-state storage. Only one zpoline site may be
    /// installed process-wide in this slice.
    pub unsafe fn publish_with(
        self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), SyscallRefusal>,
    ) -> Result<Box<InstalledZpoline>, ZpolinePublicationFailure> {
        let source_len = self.source.len();
        let page_size = self.sled_layout.page_size();
        let mut retained = Box::new(InstalledZpoline {
            prepared: self,
            trampoline: None,
            sled: None,
            observed_source: vec![0; source_len],
            observed_handler: Vec::new(),
            observed_sled: vec![0; page_size],
            captured: false,
            verified: false,
            write_attempted: false,
        });
        if let Err(reason) = claim_owner() {
            return Err(ZpolinePublicationFailure {
                failure: ZpolineFailure {
                    reason,
                    stage: FailureStage::BeforeWrite,
                },
                retained,
            });
        }
        // SAFETY: the caller supplies the complete alias, lease, finalizer,
        // stack, signal, CET, and process-lifetime contract above.
        let result = unsafe { publish_inner(&mut retained, writable_base, lease, finalize) };
        match result {
            Ok(()) => {
                ZPOLINE_OWNER.store(OWNER_INSTALLED, Ordering::Release);
                Ok(retained)
            }
            Err(failure) => {
                if failure.stage == FailureStage::KeepGated || retained.write_attempted {
                    ZPOLINE_OWNER.store(OWNER_POISONED, Ordering::Release);
                } else {
                    clear_hook_state();
                    release_owner();
                }
                Err(ZpolinePublicationFailure { failure, retained })
            }
        }
    }
}

unsafe fn publish_inner(
    retained: &mut InstalledZpoline,
    writable_base: *mut u8,
    lease: &mut QuiescenceLease<'_>,
    mut finalize: impl FnMut() -> Result<(), SyscallRefusal>,
) -> Result<(), ZpolineFailure> {
    let before = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::BeforeWrite,
    };
    let keep = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::KeepGated,
    };
    qualify_host().map_err(before)?;
    let sync = SyncCore::prepare().map_err(|error| before(sync_refusal(error)))?;
    let prepared = &retained.prepared;
    let source_range = prepared.source_range().map_err(before)?;
    if writable_base.is_null() {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "must not be null",
        }));
    }
    if writable_base as usize % 64 != prepared.base_address as usize % 64 {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "cache-line offset differs from executable alias",
        }));
    }
    if lease.is_poisoned() || lease.identity() != prepared.identity || !lease.covers(source_range) {
        return Err(before(SyscallRefusal::DependencyNotHeld));
    }
    let placement = prepared.config.placement();
    let handler_upper = prepared.sled_layout.page_size().max(16_384);
    if placement.max_mappings() < 2
        || prepared
            .sled_layout
            .page_size()
            .checked_add(handler_upper)
            .is_none_or(|needed| needed > placement.max_mapped_bytes())
    {
        return Err(before(SyscallRefusal::AllocationUnavailable));
    }
    // SAFETY: lease and alias validity are the caller's contract.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    retained.captured = true;
    if retained.observed_source != retained.prepared.source {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }

    let sled = SledMapping::probe_and_map(prepared.sled_layout.page_size()).map_err(before)?;
    retained.sled = Some(sled);
    let trampoline = ExecutableTrampoline::allocate(&retained.prepared.plan)
        .map_err(|error| before(trampoline_refusal(error)))?;
    let handler_address = trampoline.address();
    let handler_allocation = trampoline.allocation_len();
    retained.trampoline = Some(trampoline);
    if retained
        .prepared
        .sled_layout
        .page_size()
        .checked_add(handler_allocation)
        .is_none_or(|needed| needed > placement.max_mapped_bytes())
    {
        return Err(before(SyscallRefusal::AllocationUnavailable));
    }
    let handler_image = retained
        .prepared
        .plan
        .emit_at(handler_address)
        .map_err(|error| before(trampoline_refusal(error)))?;
    retained.observed_handler = vec![0; retained.trampoline.as_ref().unwrap().code_len()];
    // SAFETY: the retained trampoline mapping is readable for code_len bytes.
    unsafe { read_live(handler_address as *const u8, &mut retained.observed_handler) };
    if retained.observed_handler != handler_image.bytes() {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }

    let sled_bytes = retained.prepared.sled_image(handler_address);
    retained.observed_sled = retained
        .sled
        .as_mut()
        .expect("sled was just retained")
        .publish_bytes(&sled_bytes)
        .map_err(before)?;

    ZPOLINE_EXPECTED_SITE.store(retained.prepared.logical_pc, Ordering::Release);
    ZPOLINE_EXPECTED_RETURN.store(retained.prepared.return_pc, Ordering::Release);
    ZPOLINE_EXPECTED_NR.store(retained.prepared.syscall_nr, Ordering::Release);
    ZPOLINE_DELEGATE.store(retained.prepared.delegate as usize, Ordering::Release);

    // SAFETY: the lease still excludes every observer of the live alias.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    if retained.observed_source != retained.prepared.source {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }

    retained.write_attempted = true;
    // SAFETY: writable alias covers both site bytes and fetch is excluded.
    unsafe {
        write_site_word(
            writable_base.add(retained.prepared.offset()),
            ZPOLINE_CALL_RAX,
        )
    };
    // From this point the source may route to the sled even if a later check
    // fails, so a retained failure must not drop/unmap it.
    if let Some(sled) = retained.sled.take() {
        retained.sled = Some(sled.commit());
    }
    if let Err(error) = sync.synchronize() {
        lease.poison();
        return Err(keep(sync_refusal(error)));
    }
    if let Err(reason) = finalize() {
        lease.poison();
        return Err(keep(reason));
    }
    // SAFETY: the lease remains held through final observation.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    if retained.observed_source != retained.prepared.expected_source {
        lease.poison();
        return Err(keep(SyscallRefusal::ExpectedBytesChanged));
    }

    let sled = retained
        .sled
        .take()
        .expect("sled was retained through publication")
        .commit();
    retained.sled = Some(sled);
    retained
        .trampoline
        .as_ref()
        .expect("handler was retained through publication")
        .publish_program_counter_mappings();
    retained.verified = true;
    retained.write_attempted = false;
    Ok(())
}

impl InstalledZpoline {
    /// Restores the original `syscall` bytes, synchronizes, verifies them,
    /// and unmaps the sled under a fresh lease.
    ///
    /// The handler mapping itself follows the core trampoline process-lifetime
    /// rule and is left unreachable after the source is restored.
    ///
    /// # Safety
    /// The same alias, exclusion, finalizer, stack, signal, CET, and
    /// saved-continuation obligations as publication apply until retirement
    /// returns. No thread may execute or resume through the site during it.
    pub unsafe fn retire(
        mut self: Box<Self>,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), SyscallRefusal>,
    ) -> Result<(), ZpolinePublicationFailure> {
        // SAFETY: the caller supplies the same complete contract as publish.
        let result = unsafe { retire_inner(&mut self, writable_base, lease, finalize) };
        match result {
            Ok(()) => {
                clear_hook_state();
                ZPOLINE_OWNER.store(OWNER_EMPTY, Ordering::Release);
                Ok(())
            }
            Err(failure) => {
                if failure.stage == FailureStage::KeepGated || self.write_attempted {
                    ZPOLINE_OWNER.store(OWNER_POISONED, Ordering::Release);
                }
                Err(ZpolinePublicationFailure {
                    failure,
                    retained: self,
                })
            }
        }
    }
}

unsafe fn retire_inner(
    retained: &mut InstalledZpoline,
    writable_base: *mut u8,
    lease: &mut QuiescenceLease<'_>,
    mut finalize: impl FnMut() -> Result<(), SyscallRefusal>,
) -> Result<(), ZpolineFailure> {
    let before = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::BeforeWrite,
    };
    let keep = |reason| ZpolineFailure {
        reason,
        stage: FailureStage::KeepGated,
    };
    if !retained.verified {
        return Err(before(SyscallRefusal::StrategyUnavailableOnBackend));
    }
    qualify_host().map_err(before)?;
    let sync = SyncCore::prepare().map_err(|error| before(sync_refusal(error)))?;
    let source_range = retained.prepared.source_range().map_err(before)?;
    if writable_base.is_null() {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "must not be null",
        }));
    }
    if writable_base as usize % 64 != retained.prepared.base_address as usize % 64 {
        return Err(before(SyscallRefusal::InvalidConfig {
            field: "writable_alias",
            reason: "cache-line offset differs from executable alias",
        }));
    }
    if lease.is_poisoned()
        || lease.identity() != retained.prepared.identity
        || !lease.covers(source_range)
    {
        return Err(before(SyscallRefusal::DependencyNotHeld));
    }
    // SAFETY: the lease and alias remain valid through observation.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    retained.captured = true;
    if retained.observed_source != retained.prepared.expected_source {
        return Err(before(SyscallRefusal::ExpectedBytesChanged));
    }

    retained.write_attempted = true;
    // SAFETY: the alias covers both bytes and fetch is excluded by lease.
    unsafe {
        write_site_word(
            writable_base.add(retained.prepared.offset()),
            ORIGINAL_SYSCALL,
        )
    };
    if let Err(error) = sync.synchronize() {
        lease.poison();
        return Err(keep(sync_refusal(error)));
    }
    if let Err(reason) = finalize() {
        lease.poison();
        return Err(keep(reason));
    }
    // SAFETY: the lease remains held through restored-byte observation.
    unsafe { read_live(writable_base, &mut retained.observed_source) };
    if retained.observed_source != retained.prepared.source {
        lease.poison();
        return Err(keep(SyscallRefusal::ExpectedBytesChanged));
    }
    if let Some(sled) = retained.sled.as_mut()
        && let Err(reason) = sled.unmap()
    {
        lease.poison();
        return Err(keep(reason));
    }
    retained.captured = true;
    retained.verified = false;
    retained.write_attempted = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use liteinst::contracts::{EntryProvenance, LegalEntry, SourceIdentity};

    const BASE: u64 = 0x40_0000;

    fn identity() -> CodeIdentity {
        CodeIdentity {
            source: SourceIdentity([7; 32]),
            mapping: 11,
            generation: 3,
        }
    }

    fn entries(code: &[u8], heads: &[u64]) -> LegalEntrySet {
        LegalEntrySet {
            identity: identity(),
            scope: AddressRange::new(BASE, code.len()).unwrap(),
            provenance: EntryProvenance::Declared("zpoline unit fixture".into()),
            completeness: EntryCompleteness::Complete,
            entries: heads
                .iter()
                .map(|&address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        }
    }

    fn site<'a>(
        code: &'a [u8],
        entries: &'a LegalEntrySet,
        logical_pc: u64,
        syscall_nr: u32,
    ) -> ZpolineSite<'a> {
        ZpolineSite {
            config: SyscallStrategyConfig::new(SyscallStrategy::Zpoline),
            identity: identity(),
            code,
            base_address: BASE,
            logical_pc,
            entries,
            syscall_nr,
        }
    }

    #[test]
    fn sled_layout_and_bytes_are_exact() {
        let layout = ZpolineSledLayout::new(4096, 1023).unwrap();
        assert_eq!(layout.page_size(), 4096);
        assert_eq!(layout.max_syscall_nr(), 1023);
        assert_eq!(layout.common_entry(), 1024);
        let handler = 0x1122_3344_5566_7788;
        let sled = layout.build(handler);
        assert_eq!(sled.len(), 4096);
        assert!(
            sled[..layout.common_entry()]
                .iter()
                .all(|byte| *byte == 0x90)
        );
        for nr in 0..=layout.max_syscall_nr() {
            assert_eq!(sled[nr as usize], 0x90, "syscall {nr}");
        }
        let stub = &sled[layout.common_entry()..layout.common_entry() + COMMON_STUB_LEN];
        assert_eq!(&stub[0..5], &[0x48, 0x8d, 0x64, 0x24, 0x08]);
        assert_eq!(&stub[5..11], &[0xff, 0x25, 0, 0, 0, 0]);
        assert_eq!(&stub[11..19], &handler.to_le_bytes());
        let first = liteinst::x86::decode64(layout.common_entry() as u64, stub);
        assert_eq!(first.error, liteinst::x86::DecoderError::None);
        assert_eq!(first.instruction.mnemonic(), liteinst::x86::Mnemonic::Lea);
        assert_eq!(first.instruction.len(), 5);
        let second = liteinst::x86::decode64((layout.common_entry() + 5) as u64, &stub[5..]);
        assert_eq!(second.error, liteinst::x86::DecoderError::None);
        assert_eq!(second.instruction.mnemonic(), liteinst::x86::Mnemonic::Jmp);
        assert_eq!(second.instruction.len(), 6);
    }

    #[test]
    fn sled_layout_refuses_unrepresentable_geometry() {
        assert_eq!(
            ZpolineSledLayout::new(2048, 39),
            Err(SyscallRefusal::InvalidConfig {
                field: "page_size",
                reason: "must be a power of two and at least 4096",
            })
        );
        assert_eq!(
            ZpolineSledLayout::new(4096, 4079),
            Err(SyscallRefusal::InvalidConfig {
                field: "max_syscall_nr",
                reason: "sled common stub does not fit in one host page",
            })
        );
        assert!(ZpolineSledLayout::new(65_536, 4079).is_ok());
    }

    #[test]
    fn prepare_accepts_one_exact_first_profile_syscall() {
        let code = [0x0f, 0x05, 0xc3];
        let entries = entries(&code, &[BASE]);
        let prepared = PreparedZpoline::prepare(site(&code, &entries, BASE, 39)).unwrap();
        assert_eq!(prepared.config().strategy(), SyscallStrategy::Zpoline);
        assert_eq!(prepared.instruction().kind(), SelectedKind::Syscall);
        assert_eq!(prepared.sled_layout().max_syscall_nr(), 1023);
        assert_eq!(prepared.expected_source, [0xff, 0xd0, 0xc3]);
        assert_eq!(prepared.logical_pc, BASE);
    }

    #[test]
    fn prepare_refuses_wrong_strategy_profile_and_range() {
        let code = [0x0f, 0x05, 0xc3];
        let entries = entries(&code, &[BASE]);
        let mut wrong = site(&code, &entries, BASE, 39);
        wrong.config = SyscallStrategyConfig::new(SyscallStrategy::Trap);
        assert_eq!(
            PreparedZpoline::prepare(wrong).err(),
            Some(SyscallRefusal::InvalidConfig {
                field: "strategy",
                reason: "zpoline site requires the zpoline strategy",
            })
        );
        assert_eq!(
            PreparedZpoline::prepare(site(&code, &entries, BASE, 59)).err(),
            Some(SyscallRefusal::UnsupportedSyscallSemantics { nr: 59 })
        );
        assert_eq!(
            PreparedZpoline::prepare(site(&code, &entries, BASE, 2000)).err(),
            Some(SyscallRefusal::SyscallNumberRangeUnproven)
        );
    }

    #[test]
    fn prepare_refuses_other_entries_and_second_byte_targets() {
        let int80 = [0xcd, 0x80, 0xc3];
        let int_entries = entries(&int80, &[BASE]);
        assert_eq!(
            PreparedZpoline::prepare(site(&int80, &int_entries, BASE, 39)).err(),
            Some(SyscallRefusal::UnsupportedSyscallEntry)
        );

        let branch = [0xeb, 0x01, 0x0f, 0x05, 0xc3];
        let branch_entries = entries(&branch, &[BASE, BASE + 2]);
        assert_eq!(
            PreparedZpoline::prepare(site(&branch, &branch_entries, BASE + 2, 39)).err(),
            Some(SyscallRefusal::InteriorBranchTarget)
        );

        let shifted = [0x90, 0x0f, 0x05, 0xc3];
        let missing = entries(&shifted, &[BASE]);
        assert_eq!(
            PreparedZpoline::prepare(site(&shifted, &missing, BASE + 1, 39)).err(),
            Some(SyscallRefusal::NotInstructionHead)
        );
    }
}
