//! Relocation-aware hook trampolines for Linux on x86-64.
//!
//! A trampoline is emitted from one checked plan. It saves the System V AMD64
//! integer context, flags, red zone, and floating-point/SIMD state through AVX-512,
//! calls a hook, restores the context, executes the relocated instruction,
//! and jumps back without clobbering a register. Executable storage is mapped
//! within signed rel32 reach and is never writable through its RX alias.

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering, compiler_fence};

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock,
    code_asm::{
        CodeAssembler, eax, edx, qword_ptr, r8, r9, r10, r11, r12, r13, r14, r15, rax, rbp, rbx,
        rcx, rdi, rdx, rsi, rsp,
    },
};

use crate::patcher::{JumpPatchPlan, LiveJumpPatch, PatchError, StalenessBudget};
use crate::scanner::{InstructionScanner, ScanResult};

const SYSTEM_V_RED_ZONE_BYTES: i32 = 128;
const SAVED_INTEGER_BYTES: i32 = 16 * 8;
const HOOK_METADATA_BYTES: i32 = 2 * 8;
const FXSAVE_BYTES: i32 = 512;
const FXSAVE_ALIGNMENT: i32 = 16;
const ABSOLUTE_JUMP_BYTES: usize = 14;
const TRAMPOLINE_ALLOCATION_BYTES: usize = 4096;

const STATE_INACTIVE: u8 = 0;
const STATE_ACTIVE: u8 = 1;
const STATE_TRANSITIONING: u8 = 2;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
enum ExtendedState {
    FxSave,
    XSave { bytes: i32, mask: u64 },
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl ExtendedState {
    #[allow(unused_unsafe)]
    fn detect() -> Self {
        use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

        // SAFETY: CPUID is available in x86-64 mode.
        let features = unsafe { __cpuid(1) };
        let has_xsave = features.ecx & (1 << 26) != 0;
        let has_osxsave = features.ecx & (1 << 27) != 0;
        if has_xsave && has_osxsave {
            // SAFETY: OSXSAVE proves XGETBV is enabled for XCR0.
            // Linux can expose AMX in XCR0 while denying this thread tile-state
            // permission through XFD. Preserve the universally usable user
            // components through PKRU and leave AMX to its explicit owner.
            const USER_STATE_MASK: u64 = 0b10_1110_0111;
            let mask = unsafe { _xgetbv(0) } & USER_STATE_MASK;
            // SAFETY: CPUID leaf D is available when XSAVE is present.
            let state = unsafe { __cpuid_count(0xD, 0) };
            if mask != 0 {
                let rounded = state.ebx.checked_add(63).map(|bytes| bytes & !63);
                if let Some(bytes) = rounded.and_then(|bytes| i32::try_from(bytes).ok())
                    && bytes >= 576
                {
                    return Self::XSave { bytes, mask };
                }
            }
        }
        Self::FxSave
    }

    fn encode_save(self, assembler: &mut CodeAssembler) -> Result<(), TrampolineError> {
        let (alignment, bytes) = match self {
            Self::FxSave => (FXSAVE_ALIGNMENT, FXSAVE_BYTES),
            Self::XSave { bytes, .. } => (64, bytes),
        };
        assembler.and(rsp, -alignment).map_err(encoding_error)?;
        assembler.sub(rsp, bytes).map_err(encoding_error)?;
        match self {
            Self::FxSave => assembler.fxsave64(rsp.into()).map_err(encoding_error),
            Self::XSave { mask, .. } => {
                // XSAVE does not initialize every reserved header byte, while
                // XRSTOR requires them to be zero or raises #GP.
                assembler.xor(eax, eax).map_err(encoding_error)?;
                for offset in (512..576).step_by(8) {
                    assembler
                        .mov(qword_ptr(rsp + offset), rax)
                        .map_err(encoding_error)?;
                }
                assembler.mov(eax, mask as u32).map_err(encoding_error)?;
                assembler
                    .mov(edx, (mask >> 32) as u32)
                    .map_err(encoding_error)?;
                assembler.xsave64(rsp.into()).map_err(encoding_error)
            }
        }
    }

    fn encode_restore(self, assembler: &mut CodeAssembler) -> Result<(), TrampolineError> {
        match self {
            Self::FxSave => assembler.fxrstor64(rsp.into()).map_err(encoding_error),
            Self::XSave { mask, .. } => {
                assembler.mov(eax, mask as u32).map_err(encoding_error)?;
                assembler
                    .mov(edx, (mask >> 32) as u32)
                    .map_err(encoding_error)?;
                assembler.xrstor64(rsp.into()).map_err(encoding_error)
            }
        }
    }
}

/// Callback invoked before the displaced application instruction.
///
/// The context remains valid only for the callback. The callback must follow
/// the System V AMD64 ABI and must not unwind through generated machine code.
/// The frame preserves x87 through AVX-512 plus PKRU; callbacks must not modify
/// permission-gated AMX or other extended state outside that contract.
pub type HookCallback = unsafe extern "C" fn(*const HookContext);

/// Register snapshot observed at the instrumented instruction.
///
/// SIMD state is preserved transparently rather than exposed to callbacks.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HookContext {
    /// Address of the displaced instruction.
    pub instruction_pointer: u64,
    /// Application RSP at the displaced instruction.
    pub stack_pointer: u64,
    /// Saved R15.
    pub r15: u64,
    /// Saved R14.
    pub r14: u64,
    /// Saved R13.
    pub r13: u64,
    /// Saved R12.
    pub r12: u64,
    /// Saved R11.
    pub r11: u64,
    /// Saved R10.
    pub r10: u64,
    /// Saved R9.
    pub r9: u64,
    /// Saved R8.
    pub r8: u64,
    /// Saved RDI.
    pub rdi: u64,
    /// Saved RSI.
    pub rsi: u64,
    /// Saved RBP.
    pub rbp: u64,
    /// Saved RBX.
    pub rbx: u64,
    /// Saved RDX.
    pub rdx: u64,
    /// Saved RCX.
    pub rcx: u64,
    /// Saved RAX.
    pub rax: u64,
    /// Saved RFLAGS.
    pub rflags: u64,
}

/// Checked byte lengths for the sections of one trampoline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrampolineLayout {
    /// Context-save and instrumentation-call bytes.
    pub instrumentation_len: usize,
    /// Relocated application instruction bytes.
    pub relocated_len: usize,
    /// Context-restore bytes.
    pub restore_len: usize,
    /// Control-transfer bytes returning to application code.
    pub return_len: usize,
}

impl TrampolineLayout {
    /// Returns the total allocation size, or None if the sum overflows.
    pub fn total_len(self) -> Option<usize> {
        self.instrumentation_len
            .checked_add(self.relocated_len)?
            .checked_add(self.restore_len)?
            .checked_add(self.return_len)
    }
}

/// Complete emitted bytes and section boundaries for a trampoline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrampolineImage {
    bytes: Vec<u8>,
    layout: TrampolineLayout,
}

impl TrampolineImage {
    /// Returns the emitted machine code.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the checked section lengths.
    pub const fn layout(&self) -> TrampolineLayout {
        self.layout
    }
}

/// Errors produced while planning, emitting, allocating, or toggling a hook.
#[derive(Debug)]
pub enum TrampolineError {
    /// The requested address is not an instruction head in the scan.
    SiteNotFound {
        /// Requested executable address.
        address: u64,
    },
    /// The direct jump cannot displace this instruction by itself.
    InstructionTooShort {
        /// Instruction address.
        address: u64,
        /// Decoded instruction length.
        instruction_len: usize,
    },
    /// Computing the address after the displaced instruction overflowed.
    ReturnAddressOverflow {
        /// Instruction address.
        address: u64,
        /// Decoded instruction length.
        instruction_len: usize,
    },
    /// iced-x86 could not encode generated or relocated code.
    Encoding {
        /// Encoder diagnostic.
        message: String,
    },
    /// An address cannot be represented by this process.
    AddressNotRepresentable {
        /// Address that failed conversion.
        address: u64,
    },
    /// The operating-system page size is unavailable or unsupported.
    InvalidPageSize,
    /// Creating or publishing executable backing storage failed.
    BackingStore {
        /// Failed operation.
        operation: &'static str,
        /// Operating-system error number.
        errno: i32,
    },
    /// Reading or parsing the process memory map failed.
    ProcessMaps {
        /// Diagnostic for the unavailable or malformed map.
        message: String,
    },
    /// No free page could be mapped within signed rel32 reach.
    NoReachableMapping,
    /// Emitted code does not fit in its executable allocation.
    CodeTooLarge {
        /// Emitted code bytes.
        code_len: usize,
        /// Available allocation bytes.
        allocation_len: usize,
    },
    /// A hook toggle raced another toggle on the same site.
    TransitionInProgress,
    /// M2 rejected patch planning, binding, or publication.
    Patch(PatchError),
    /// Trampolines are unavailable on this target.
    UnsupportedPlatform,
}

impl fmt::Display for TrampolineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SiteNotFound { address } => {
                write!(formatter, "no scanned instruction starts at {address:#x}")
            }
            Self::InstructionTooShort {
                address,
                instruction_len,
            } => write!(
                formatter,
                "instruction at {address:#x} is {instruction_len} bytes; direct redirection needs at least five"
            ),
            Self::ReturnAddressOverflow {
                address,
                instruction_len,
            } => write!(
                formatter,
                "instruction at {address:#x} with length {instruction_len} has no return address"
            ),
            Self::Encoding { message } => {
                write!(formatter, "machine-code encoding failed: {message}")
            }
            Self::AddressNotRepresentable { address } => {
                write!(formatter, "address {address:#x} is not representable")
            }
            Self::InvalidPageSize => formatter.write_str("invalid operating-system page size"),
            Self::BackingStore { operation, errno } => {
                write!(formatter, "{operation} failed with errno {errno}")
            }
            Self::ProcessMaps { message } => {
                write!(formatter, "cannot find a near mapping: {message}")
            }
            Self::NoReachableMapping => {
                formatter.write_str("no free executable page is within signed rel32 reach")
            }
            Self::CodeTooLarge {
                code_len,
                allocation_len,
            } => write!(
                formatter,
                "{code_len}-byte trampoline exceeds {allocation_len}-byte allocation"
            ),
            Self::TransitionInProgress => {
                formatter.write_str("another thread is toggling this hook")
            }
            Self::Patch(source) => write!(formatter, "patch operation failed: {source}"),
            Self::UnsupportedPlatform => formatter.write_str("trampolines require Linux on x86-64"),
        }
    }
}

impl std::error::Error for TrampolineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Patch(source) => Some(source),
            _ => None,
        }
    }
}

impl From<PatchError> for TrampolineError {
    fn from(source: PatchError) -> Self {
        Self::Patch(source)
    }
}

/// Immutable relocation and dispatch plan for one instruction.
#[derive(Clone, Debug)]
pub struct TrampolinePlan {
    execute_address: u64,
    return_address: u64,
    hook: HookCallback,
    instruction: Instruction,
}

impl TrampolinePlan {
    /// Builds a one-instruction plan from an M1 scan.
    ///
    /// Lengths from 5 through x86's 15-byte maximum are accepted. Shorter
    /// instructions are rejected rather than overwriting a later entry point.
    pub fn from_scan(
        scan: &ScanResult,
        execute_address: u64,
        hook: HookCallback,
    ) -> Result<Self, TrampolineError> {
        let site = scan
            .site(execute_address)
            .ok_or(TrampolineError::SiteNotFound {
                address: execute_address,
            })?;
        if site.instruction_len() < 5 {
            return Err(TrampolineError::InstructionTooShort {
                address: execute_address,
                instruction_len: site.instruction_len(),
            });
        }
        let instruction = scan
            .instructions()
            .iter()
            .find(|instruction| instruction.address() == execute_address)
            .ok_or(TrampolineError::SiteNotFound {
                address: execute_address,
            })?
            .instruction()
            .to_owned();
        let return_address = execute_address
            .checked_add(site.instruction_len() as u64)
            .ok_or(TrampolineError::ReturnAddressOverflow {
                address: execute_address,
                instruction_len: site.instruction_len(),
            })?;
        Ok(Self {
            execute_address,
            return_address,
            hook,
            instruction,
        })
    }

    /// Returns the displaced instruction address.
    pub const fn execute_address(&self) -> u64 {
        self.execute_address
    }

    /// Returns the first application address after the displaced instruction.
    pub const fn return_address(&self) -> u64 {
        self.return_address
    }

    /// Returns the displaced instruction length.
    pub const fn displaced_len(&self) -> usize {
        self.instruction.len()
    }

    /// Emits this plan at an exact executable address.
    pub fn emit_at(&self, address: u64) -> Result<TrampolineImage, TrampolineError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = address;
            return Err(TrampolineError::UnsupportedPlatform);
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let extended_state = ExtendedState::detect();
            let instrumentation = self.encode_instrumentation(address, extended_state)?;
            let restore_address = address
                .checked_add(instrumentation.len() as u64)
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let restore = encode_restore(restore_address, extended_state)?;
            let relocated_address = restore_address
                .checked_add(restore.len() as u64)
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let relocated = BlockEncoder::encode(
                64,
                InstructionBlock::new(core::slice::from_ref(&self.instruction), relocated_address),
                BlockEncoderOptions::NONE,
            )
            .map_err(encoding_error)?
            .code_buffer;
            let return_jump = absolute_indirect_jump(self.return_address);
            let layout = TrampolineLayout {
                instrumentation_len: instrumentation.len(),
                relocated_len: relocated.len(),
                restore_len: restore.len(),
                return_len: return_jump.len(),
            };
            let total_len = layout.total_len().ok_or(TrampolineError::CodeTooLarge {
                code_len: usize::MAX,
                allocation_len: TRAMPOLINE_ALLOCATION_BYTES,
            })?;
            let mut bytes = Vec::with_capacity(total_len);
            bytes.extend_from_slice(&instrumentation);
            bytes.extend_from_slice(&restore);
            bytes.extend_from_slice(&relocated);
            bytes.extend_from_slice(&return_jump);
            debug_assert_eq!(bytes.len(), total_len);
            Ok(TrampolineImage { bytes, layout })
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn encode_instrumentation(
        &self,
        address: u64,
        extended_state: ExtendedState,
    ) -> Result<Vec<u8>, TrampolineError> {
        let mut assembler = CodeAssembler::new(64).map_err(encoding_error)?;
        assembler
            .lea(rsp, rsp - SYSTEM_V_RED_ZONE_BYTES)
            .map_err(encoding_error)?;
        assembler.pushfq().map_err(encoding_error)?;
        for register in [
            rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
        ] {
            assembler.push(register).map_err(encoding_error)?;
        }
        assembler
            .lea(rax, rsp + SYSTEM_V_RED_ZONE_BYTES + SAVED_INTEGER_BYTES)
            .map_err(encoding_error)?;
        assembler.push(rax).map_err(encoding_error)?;
        assembler
            .mov(rax, self.execute_address)
            .map_err(encoding_error)?;
        assembler.push(rax).map_err(encoding_error)?;
        assembler.mov(r12, rsp).map_err(encoding_error)?;
        extended_state.encode_save(&mut assembler)?;
        assembler.cld().map_err(encoding_error)?;
        assembler.mov(rdi, r12).map_err(encoding_error)?;
        assembler
            .mov(rax, self.hook as usize as u64)
            .map_err(encoding_error)?;
        assembler.call(rax).map_err(encoding_error)?;
        assembler.assemble(address).map_err(encoding_error)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn encode_restore(address: u64, extended_state: ExtendedState) -> Result<Vec<u8>, TrampolineError> {
    let mut assembler = CodeAssembler::new(64).map_err(encoding_error)?;
    extended_state.encode_restore(&mut assembler)?;
    assembler.mov(rsp, r12).map_err(encoding_error)?;
    assembler
        .add(rsp, HOOK_METADATA_BYTES)
        .map_err(encoding_error)?;
    for register in [
        r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax,
    ] {
        assembler.pop(register).map_err(encoding_error)?;
    }
    assembler.popfq().map_err(encoding_error)?;
    assembler
        .lea(rsp, rsp + SYSTEM_V_RED_ZONE_BYTES)
        .map_err(encoding_error)?;
    assembler.assemble(address).map_err(encoding_error)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn encoding_error(error: iced_x86::IcedError) -> TrampolineError {
    TrampolineError::Encoding {
        message: error.to_string(),
    }
}

fn absolute_indirect_jump(target: u64) -> [u8; ABSOLUTE_JUMP_BYTES] {
    let mut bytes = [0_u8; ABSOLUTE_JUMP_BYTES];
    bytes[..6].copy_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]);
    bytes[6..].copy_from_slice(&target.to_le_bytes());
    bytes
}

/// Process-lifetime executable trampoline mapping.
///
/// The writable alias is removed before construction returns. The RX page is
/// intentionally not unmapped on drop because another thread may have fetched
/// its address before concurrent deactivation.
pub struct ExecutableTrampoline {
    address: u64,
    allocation_len: usize,
    code_len: usize,
    layout: TrampolineLayout,
}

impl ExecutableTrampoline {
    /// Allocates a reachable page, emits the plan, and publishes an RX mapping.
    pub fn allocate(plan: &TrampolinePlan) -> Result<Self, TrampolineError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = plan;
            return Err(TrampolineError::UnsupportedPlatform);
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let mapping = PendingMapping::allocate_near(plan.execute_address)?;
            let address = mapping.executable as usize as u64;
            let image = plan.emit_at(address)?;
            if image.bytes.len() > mapping.len {
                return Err(TrampolineError::CodeTooLarge {
                    code_len: image.bytes.len(),
                    allocation_len: mapping.len,
                });
            }
            mapping.publish(&image)
        }
    }

    /// Returns the executable entry address.
    pub const fn address(&self) -> u64 {
        self.address
    }

    /// Returns the executable mapping size.
    pub const fn allocation_len(&self) -> usize {
        self.allocation_len
    }

    /// Returns the number of initialized machine-code bytes.
    pub const fn code_len(&self) -> usize {
        self.code_len
    }

    /// Returns the emitted section lengths.
    pub const fn layout(&self) -> TrampolineLayout {
        self.layout
    }

    fn discard(self) {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            // SAFETY: this unpublished object exclusively owns the RX mapping.
            unsafe {
                libc::munmap(
                    self.address as usize as *mut libc::c_void,
                    self.allocation_len,
                );
            }
        }
    }
}

/// Scanner and mapping inputs for installing one hook.
pub struct HookSite<'a> {
    scanner: &'a InstructionScanner,
    scan: &'a ScanResult,
    code: &'a [u8],
    region_base: u64,
    execute_address: u64,
    writable_address: *mut u8,
}

impl<'a> HookSite<'a> {
    /// Describes an executable instruction and its writable alias.
    pub const fn new(
        scanner: &'a InstructionScanner,
        scan: &'a ScanResult,
        code: &'a [u8],
        region_base: u64,
        execute_address: u64,
        writable_address: *mut u8,
    ) -> Self {
        Self {
            scanner,
            scan,
            code,
            region_base,
            execute_address,
            writable_address,
        }
    }
}
/// A generated trampoline bound to the M2 live patcher.
pub struct InstalledHook {
    trampoline: ExecutableTrampoline,
    patch: LiveJumpPatch,
    state: AtomicU8,
}

impl InstalledHook {
    /// Generates and binds an initially inactive hook.
    ///
    /// # Safety
    ///
    /// The writable alias in site must satisfy LiveJumpPatch::bind and remain
    /// valid for the process lifetime. Its code and scan must describe the
    /// executable region. The callback must remain callable for the
    /// process lifetime and must not unwind across its C ABI boundary.
    pub unsafe fn install(
        site: HookSite<'_>,
        hook: HookCallback,
        staleness: StalenessBudget,
    ) -> Result<Self, TrampolineError> {
        let trampoline_plan = TrampolinePlan::from_scan(site.scan, site.execute_address, hook)?;
        let trampoline = ExecutableTrampoline::allocate(&trampoline_plan)?;
        let patch_plan = match JumpPatchPlan::from_scan(
            site.scanner,
            site.scan,
            site.code,
            site.region_base,
            site.execute_address,
            trampoline.address,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                trampoline.discard();
                return Err(error.into());
            }
        };
        // SAFETY: forwarded from this method's mapping-lifetime contract.
        let patch =
            match unsafe { LiveJumpPatch::bind(patch_plan, site.writable_address, staleness) } {
                Ok(patch) => patch,
                Err(error) => {
                    trampoline.discard();
                    return Err(error.into());
                }
            };
        Ok(Self {
            trampoline,
            patch,
            state: AtomicU8::new(STATE_INACTIVE),
        })
    }

    /// Returns the generated executable trampoline.
    pub const fn trampoline(&self) -> &ExecutableTrampoline {
        &self.trampoline
    }

    /// Returns whether the redirect is fully active.
    pub fn is_active(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_ACTIVE
    }

    /// Activates the hook, returning whether code bytes changed.
    pub fn activate(&self) -> Result<bool, TrampolineError> {
        match self.state.compare_exchange(
            STATE_INACTIVE,
            STATE_TRANSITIONING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // SAFETY: install captured the process-lifetime binding contract.
                match unsafe { self.patch.apply() } {
                    Ok(()) => {
                        self.state.store(STATE_ACTIVE, Ordering::Release);
                        Ok(true)
                    }
                    Err(error) => {
                        self.state.store(STATE_INACTIVE, Ordering::Release);
                        Err(error.into())
                    }
                }
            }
            Err(STATE_ACTIVE) => Ok(false),
            Err(_) => Err(TrampolineError::TransitionInProgress),
        }
    }

    /// Deactivates the hook, returning whether code bytes changed.
    pub fn deactivate(&self) -> Result<bool, TrampolineError> {
        match self.state.compare_exchange(
            STATE_ACTIVE,
            STATE_TRANSITIONING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // SAFETY: install captured the process-lifetime binding contract.
                match unsafe { self.patch.revert() } {
                    Ok(()) => {
                        self.state.store(STATE_INACTIVE, Ordering::Release);
                        Ok(true)
                    }
                    Err(error) => {
                        self.state.store(STATE_ACTIVE, Ordering::Release);
                        Err(error.into())
                    }
                }
            }
            Err(STATE_INACTIVE) => Ok(false),
            Err(_) => Err(TrampolineError::TransitionInProgress),
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct PendingMapping {
    fd: libc::c_int,
    writable: *mut libc::c_void,
    executable: *mut libc::c_void,
    len: usize,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl PendingMapping {
    fn allocate_near(execute_address: u64) -> Result<Self, TrampolineError> {
        let page_size = page_size()?;
        let len = TRAMPOLINE_ALLOCATION_BYTES.max(page_size);
        let len = len
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or(TrampolineError::InvalidPageSize)?;
        let name = b"liteinst2-trampoline\0";
        // SAFETY: valid NUL-terminated name and supported memfd flags.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr().cast::<libc::c_char>(),
                libc::MFD_CLOEXEC,
            ) as libc::c_int
        };
        if fd < 0 {
            return Err(os_error("memfd_create"));
        }
        let mut mapping = Self {
            fd,
            writable: core::ptr::null_mut(),
            executable: core::ptr::null_mut(),
            len,
        };
        // SAFETY: fd is live and len is a positive page multiple.
        if unsafe { libc::ftruncate(fd, len as libc::off_t) } != 0 {
            return Err(os_error("ftruncate"));
        }
        // SAFETY: creates a shared, non-executable writable alias.
        let writable = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if writable == libc::MAP_FAILED {
            return Err(os_error("mmap writable alias"));
        }
        mapping.writable = writable;

        let next_ip = execute_address
            .checked_add(crate::patcher::NEAR_JUMP_BYTES as u64)
            .ok_or(TrampolineError::AddressNotRepresentable {
                address: execute_address,
            })?;
        for candidate in near_candidates(next_ip, len, page_size)? {
            // SAFETY: MAP_FIXED_NOREPLACE never replaces an existing VMA.
            let executable = unsafe {
                libc::mmap(
                    candidate as *mut libc::c_void,
                    len,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                    fd,
                    0,
                )
            };
            if executable == libc::MAP_FAILED {
                continue;
            }
            if executable as usize != candidate {
                // SAFETY: executable is the mapping just returned by mmap.
                unsafe { libc::munmap(executable, len) };
                continue;
            }
            mapping.executable = executable;
            return Ok(mapping);
        }
        Err(TrampolineError::NoReachableMapping)
    }

    fn publish(mut self, image: &TrampolineImage) -> Result<ExecutableTrampoline, TrampolineError> {
        // SAFETY: the writable alias is large enough and does not overlap bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                image.bytes.as_ptr(),
                self.writable.cast::<u8>(),
                image.bytes.len(),
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: writable is the live mapping returned by mmap.
        if unsafe { libc::munmap(self.writable, self.len) } != 0 {
            return Err(os_error("munmap writable alias"));
        }
        self.writable = core::ptr::null_mut();
        // SAFETY: fd is live; mappings retain their backing object.
        if unsafe { libc::close(self.fd) } != 0 {
            return Err(os_error("close trampoline memfd"));
        }
        self.fd = -1;
        let address = self.executable as usize as u64;
        self.executable = core::ptr::null_mut();
        Ok(ExecutableTrampoline {
            address,
            allocation_len: self.len,
            code_len: image.bytes.len(),
            layout: image.layout,
        })
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for PendingMapping {
    fn drop(&mut self) {
        if !self.writable.is_null() {
            // SAFETY: this object owns the live mapping.
            unsafe { libc::munmap(self.writable, self.len) };
        }
        if !self.executable.is_null() {
            // SAFETY: this object owns the live mapping.
            unsafe { libc::munmap(self.executable, self.len) };
        }
        if self.fd >= 0 {
            // SAFETY: this object owns the live descriptor.
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn page_size() -> Result<usize, TrampolineError> {
    // SAFETY: sysconf has no pointer arguments.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let value = usize::try_from(value).map_err(|_| TrampolineError::InvalidPageSize)?;
    if value == 0 || !value.is_power_of_two() {
        return Err(TrampolineError::InvalidPageSize);
    }
    Ok(value)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn os_error(operation: &'static str) -> TrampolineError {
    TrampolineError::BackingStore {
        operation,
        errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn near_candidates(
    next_ip: u64,
    len: usize,
    page_size: usize,
) -> Result<Vec<usize>, TrampolineError> {
    let next_ip = usize::try_from(next_ip)
        .map_err(|_| TrampolineError::AddressNotRepresentable { address: next_ip })?;
    let low = (next_ip as i128 + i32::MIN as i128)
        .max(page_size as i128)
        .max(0) as usize;
    let high = (next_ip as i128 + i32::MAX as i128).min((usize::MAX - len) as i128) as usize;
    if low > high {
        return Err(TrampolineError::NoReachableMapping);
    }
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|error| {
        TrampolineError::ProcessMaps {
            message: error.to_string(),
        }
    })?;
    let mut ranges = Vec::new();
    for line in maps.lines() {
        let field = line
            .split_whitespace()
            .next()
            .ok_or_else(|| TrampolineError::ProcessMaps {
                message: format!("missing address range in {line:?}"),
            })?;
        let (start, end) = field
            .split_once('-')
            .ok_or_else(|| TrampolineError::ProcessMaps {
                message: format!("malformed address range {field:?}"),
            })?;
        let start =
            usize::from_str_radix(start, 16).map_err(|error| TrampolineError::ProcessMaps {
                message: format!("invalid range start {start:?}: {error}"),
            })?;
        let end = usize::from_str_radix(end, 16).map_err(|error| TrampolineError::ProcessMaps {
            message: format!("invalid range end {end:?}: {error}"),
        })?;
        if start < end {
            ranges.push((start, end));
        }
    }
    ranges.sort_unstable();
    let mut candidates = Vec::new();
    let mut cursor = low;
    for (start, end) in ranges {
        if end <= cursor {
            continue;
        }
        if start > cursor {
            add_gap_candidate(
                &mut candidates,
                cursor,
                start,
                low,
                high,
                next_ip,
                len,
                page_size,
            );
        }
        cursor = cursor.max(end);
        if cursor > high.saturating_add(len) {
            break;
        }
    }
    add_gap_candidate(
        &mut candidates,
        cursor,
        usize::MAX,
        low,
        high,
        next_ip,
        len,
        page_size,
    );
    candidates.sort_unstable_by_key(|candidate| candidate.abs_diff(next_ip));
    candidates.dedup();
    Ok(candidates)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(clippy::too_many_arguments)]
fn add_gap_candidate(
    candidates: &mut Vec<usize>,
    gap_start: usize,
    gap_end: usize,
    low: usize,
    high: usize,
    preferred: usize,
    len: usize,
    page_size: usize,
) {
    let min_start = align_up(gap_start.max(low), page_size);
    let Some(last_start) = gap_end.checked_sub(len) else {
        return;
    };
    let max_start = align_down(last_start.min(high), page_size);
    if min_start > max_start {
        return;
    }
    candidates.push(align_down(preferred, page_size).clamp(min_start, max_start));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn align_down(value: usize, alignment: usize) -> usize {
    value & !(alignment - 1)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn align_up(value: usize, alignment: usize) -> usize {
    value.saturating_add(alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::{HookContext, TrampolineError, TrampolineLayout, TrampolinePlan};
    use crate::scanner::InstructionScanner;

    unsafe extern "C" fn noop_hook(_context: *const HookContext) {}

    fn plan(code: &[u8], base: u64) -> Result<TrampolinePlan, TrampolineError> {
        let scan = InstructionScanner::default()
            .scan(code, base)
            .expect("fixture must decode");
        TrampolinePlan::from_scan(&scan, base, noop_hook)
    }

    #[test]
    fn total_length_includes_every_section() {
        let layout = TrampolineLayout {
            instrumentation_len: 32,
            relocated_len: 12,
            restore_len: 16,
            return_len: 5,
        };
        assert_eq!(layout.total_len(), Some(65));
    }

    #[test]
    fn total_length_rejects_overflow() {
        let layout = TrampolineLayout {
            instrumentation_len: usize::MAX,
            relocated_len: 1,
            ..TrampolineLayout::default()
        };
        assert_eq!(layout.total_len(), None);
    }

    #[test]
    fn rejects_short_instruction_without_consuming_next_head() {
        let error = plan(&[0x48, 0x89, 0xF8], 0x1000).unwrap_err();
        assert!(matches!(
            error,
            TrampolineError::InstructionTooShort {
                address: 0x1000,
                instruction_len: 3
            }
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn emits_checked_layouts_for_five_seven_and_ten_byte_instructions() {
        let fixtures: &[&[u8]] = &[
            &[0xB8, 1, 0, 0, 0],
            &[0x48, 0x8D, 0x05, 0, 0, 0, 0],
            &[0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8],
        ];
        for (index, code) in fixtures.iter().enumerate() {
            let base = 0x10_0000 + index as u64 * 0x1000;
            let plan = plan(code, base).unwrap();
            let image = plan.emit_at(base + 0x10_0000).unwrap();
            assert_eq!(plan.displaced_len(), code.len());
            assert_eq!(plan.return_address(), base + code.len() as u64);
            assert_eq!(image.layout().total_len(), Some(image.bytes().len()));
            assert_eq!(image.layout().return_len, 14);
            assert_eq!(
                &image.bytes()[image.bytes().len() - 8..],
                &plan.return_address().to_le_bytes()
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn reencodes_rip_relative_memory_for_the_trampoline_address() {
        use iced_x86::{Decoder, DecoderOptions};

        let base = 0x20_0000;
        let code = [0x8B, 0x05, 0x34, 0x12, 0, 0];
        let original_target = base + code.len() as u64 + 0x1234;
        let plan = plan(&code, base).unwrap();
        let trampoline_address = base + 0x20_0000;
        let image = plan.emit_at(trampoline_address).unwrap();
        let start = image.layout().instrumentation_len + image.layout().restore_len;
        let relocated_ip = trampoline_address
            + image.layout().instrumentation_len as u64
            + image.layout().restore_len as u64;
        let end = start + image.layout().relocated_len;
        let instruction = Decoder::with_ip(
            64,
            &image.bytes()[start..end],
            relocated_ip,
            DecoderOptions::NONE,
        )
        .decode();
        assert_eq!(instruction.ip_rel_memory_address(), original_target);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn relocates_relative_calls_and_expands_out_of_range_branches() {
        use iced_x86::{Decoder, DecoderOptions};

        let call_base = 0x30_0000_u64;
        let call_target = call_base + 0x2000;
        let call_displacement =
            i32::try_from(call_target as i128 - (call_base + 5) as i128).unwrap();
        let mut call = [0_u8; 5];
        call[0] = 0xE8;
        call[1..].copy_from_slice(&call_displacement.to_le_bytes());
        let call_plan = plan(&call, call_base).unwrap();
        let call_trampoline = call_base + 0x10_0000;
        let call_image = call_plan.emit_at(call_trampoline).unwrap();
        let call_start = call_image.layout().instrumentation_len + call_image.layout().restore_len;
        let call_ip = call_trampoline + call_start as u64;
        let relocated_call = Decoder::with_ip(
            64,
            &call_image.bytes()[call_start..call_start + call_image.layout().relocated_len],
            call_ip,
            DecoderOptions::NONE,
        )
        .decode();
        assert_eq!(relocated_call.near_branch_target(), call_target);

        let branch_base = 0x40_0000_u64;
        let branch = [0x0F, 0x84, 0, 1, 0, 0];
        let branch_plan = plan(&branch, branch_base).unwrap();
        let branch_image = branch_plan.emit_at(0x2_0000_0000).unwrap();
        assert!(branch_image.layout().relocated_len > branch.len());
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod live {
        use core::arch::asm;
        use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::{Arc, Barrier, Mutex, MutexGuard};
        use std::thread;
        use std::time::{Duration, Instant};

        use super::{HookContext, InstructionScanner};
        use crate::patcher::StalenessBudget;
        use crate::trampoline::{HookSite, InstalledHook};

        const PAGE_BYTES: usize = 4096;
        const STALENESS_TICKS: u64 = 3_000;
        static TEST_LOCK: Mutex<()> = Mutex::new(());
        static CALLBACKS: AtomicU64 = AtomicU64::new(0);
        static LAST_IP: AtomicU64 = AtomicU64::new(0);

        fn serial_guard() -> MutexGuard<'static, ()> {
            TEST_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
        static LAST_RDI: AtomicU64 = AtomicU64::new(0);

        unsafe extern "C" fn record_hook(context: *const HookContext) {
            // SAFETY: generated code passes a live HookContext for this call.
            let context = unsafe { &*context };
            LAST_IP.store(context.instruction_pointer, Ordering::Relaxed);
            LAST_RDI.store(context.rdi, Ordering::Relaxed);
            CALLBACKS.fetch_add(1, Ordering::Relaxed);
        }

        unsafe extern "C" fn clobber_flags_hook(_context: *const HookContext) {
            let mut scratch: u64;
            // SAFETY: deliberately clobbers caller-saved RAX and arithmetic flags.
            unsafe {
                asm!(
                    "mov {scratch}, 0xffff",
                    "add {scratch}, 1",
                    scratch = lateout(reg) scratch,
                    options(nostack),
                );
            }
            core::hint::black_box(scratch);
            CALLBACKS.fetch_add(1, Ordering::Relaxed);
        }

        unsafe extern "C" fn clobber_xmm_hook(_context: *const HookContext) {
            // SAFETY: XMM0 is caller-saved; the trampoline must restore it.
            unsafe {
                asm!("pxor xmm0, xmm0", out("xmm0") _, options(nostack, preserves_flags));
            }
            CALLBACKS.fetch_add(1, Ordering::Relaxed);
        }

        unsafe extern "C" fn clobber_ymm_hook(_context: *const HookContext) {
            // SAFETY: YMM1 is caller-saved; XSAVE must restore its upper lane.
            unsafe {
                asm!(
                    "vpxor ymm1, ymm1, ymm1",
                    out("ymm1") _,
                    options(nostack, preserves_flags),
                );
            }
            CALLBACKS.fetch_add(1, Ordering::Relaxed);
        }
        struct DualMapping {
            writable: *mut u8,
            executable: *mut u8,
        }

        impl DualMapping {
            fn new() -> Self {
                let name = b"liteinst2-trampoline-test\0";
                // SAFETY: valid NUL-terminated name and flags.
                let fd = unsafe {
                    libc::syscall(
                        libc::SYS_memfd_create,
                        name.as_ptr().cast::<libc::c_char>(),
                        libc::MFD_CLOEXEC,
                    ) as libc::c_int
                };
                assert!(fd >= 0, "memfd_create failed");
                // SAFETY: fd is valid and the size is representable.
                assert_eq!(unsafe { libc::ftruncate(fd, PAGE_BYTES as libc::off_t) }, 0);
                // SAFETY: map a writable, non-executable shared alias.
                let writable = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        PAGE_BYTES,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        fd,
                        0,
                    )
                };
                assert_ne!(writable, libc::MAP_FAILED);
                // SAFETY: map a separate read-execute shared alias.
                let executable = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        PAGE_BYTES,
                        libc::PROT_READ | libc::PROT_EXEC,
                        libc::MAP_SHARED,
                        fd,
                        0,
                    )
                };
                assert_ne!(executable, libc::MAP_FAILED);
                // SAFETY: both mappings retain the backing object.
                assert_eq!(unsafe { libc::close(fd) }, 0);
                Self {
                    writable: writable.cast(),
                    executable: executable.cast(),
                }
            }

            fn write(&self, offset: usize, bytes: &[u8]) {
                assert!(offset + bytes.len() <= PAGE_BYTES);
                // SAFETY: the writable mapping contains the requested range.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        self.writable.add(offset),
                        bytes.len(),
                    );
                }
            }

            fn write_u32(&self, offset: usize, value: u32) {
                self.write(offset, &value.to_le_bytes());
            }

            fn executable_address(&self, offset: usize) -> u64 {
                // SAFETY: tests keep offsets within the mapping.
                unsafe { self.executable.add(offset) as usize as u64 }
            }

            fn writable_address(&self, offset: usize) -> *mut u8 {
                // SAFETY: tests keep offsets within the mapping.
                unsafe { self.writable.add(offset) }
            }
        }

        fn install(
            mapping: &DualMapping,
            function_offset: usize,
            code: &[u8],
            site_offset: usize,
            hook: unsafe extern "C" fn(*const HookContext),
        ) -> InstalledHook {
            mapping.write(function_offset, code);
            let scanner = InstructionScanner::default();
            let region_base = mapping.executable_address(function_offset);
            let scan = scanner.scan(code, region_base).unwrap();
            // SAFETY: the test leaks both aliases for the process lifetime.
            unsafe {
                InstalledHook::install(
                    HookSite::new(
                        &scanner,
                        &scan,
                        code,
                        region_base,
                        region_base + site_offset as u64,
                        mapping.writable_address(function_offset + site_offset),
                    ),
                    hook,
                    StalenessBudget::new(STALENESS_TICKS).unwrap(),
                )
                .unwrap()
            }
        }

        fn mapping_permissions(address: u64) -> String {
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
            maps.lines()
                .find_map(|line| {
                    let mut fields = line.split_whitespace();
                    let range = fields.next()?;
                    let permissions = fields.next()?;
                    let (start, end) = range.split_once('-')?;
                    let start = u64::from_str_radix(start, 16).ok()?;
                    let end = u64::from_str_radix(end, 16).ok()?;
                    (start <= address && address < end).then(|| permissions.to_owned())
                })
                .expect("trampoline address must have a VMA")
        }

        #[test]
        fn hook_fires_preserves_result_and_toggles_idempotently() {
            let _guard = serial_guard();
            CALLBACKS.store(0, Ordering::Relaxed);
            LAST_IP.store(0, Ordering::Relaxed);
            LAST_RDI.store(0, Ordering::Relaxed);

            let mapping = DualMapping::new();
            let offset = 60;
            let code = [0xB8, 7, 0, 0, 0, 0x01, 0xF8, 0xC3];
            let hook = install(&mapping, offset, &code, 0, record_hook);
            // SAFETY: executable bytes implement extern C fn(u32) -> u32.
            let function: unsafe extern "C" fn(u32) -> u32 =
                unsafe { core::mem::transmute(mapping.executable_address(offset) as usize) };

            assert_eq!(unsafe { function(5) }, 12);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 0);
            assert!(hook.activate().unwrap());
            assert!(!hook.activate().unwrap());
            assert!(hook.is_active());
            assert_eq!(unsafe { function(5) }, 12);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
            assert_eq!(
                LAST_IP.load(Ordering::Relaxed),
                mapping.executable_address(offset)
            );
            assert_eq!(LAST_RDI.load(Ordering::Relaxed), 5);
            assert!(hook.deactivate().unwrap());
            assert!(!hook.deactivate().unwrap());
            assert!(!hook.is_active());
            assert_eq!(unsafe { function(9) }, 16);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);

            let next_ip = mapping.executable_address(offset) + 5;
            let displacement = i128::from(hook.trampoline().address()) - i128::from(next_ip);
            assert!(i32::try_from(displacement).is_ok());
            let permissions = mapping_permissions(hook.trampoline().address());
            assert!(permissions.contains('x'));
            assert!(!permissions.contains('w'));
        }

        #[test]
        fn relocates_rip_relative_load_and_returns_to_original_code() {
            let _guard = serial_guard();
            CALLBACKS.store(0, Ordering::Relaxed);
            let mapping = DualMapping::new();
            let function_offset = 128;
            let data_offset = 512;
            let function_address = mapping.executable_address(function_offset);
            let displacement = i32::try_from(
                mapping.executable_address(data_offset) as i128 - (function_address + 6) as i128,
            )
            .unwrap();
            let mut code = [0_u8; 8];
            code[..2].copy_from_slice(&[0x8B, 0x05]);
            code[2..6].copy_from_slice(&displacement.to_le_bytes());
            code[6] = 0xC3;
            code[7] = 0x90;
            mapping.write_u32(data_offset, 0x1234_5678);
            let hook = install(&mapping, function_offset, &code, 0, record_hook);
            // SAFETY: fixture is an extern C function returning u32.
            let function: unsafe extern "C" fn() -> u32 =
                unsafe { core::mem::transmute(function_address as usize) };

            assert_eq!(unsafe { function() }, 0x1234_5678);
            hook.activate().unwrap();
            assert_eq!(unsafe { function() }, 0x1234_5678);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
            hook.deactivate().unwrap();
        }

        #[test]
        fn relocates_relative_call_and_resumes_after_its_return() {
            let _guard = serial_guard();
            CALLBACKS.store(0, Ordering::Relaxed);
            let mapping = DualMapping::new();
            let function_offset = 192;
            let helper_offset = 640;
            let function_address = mapping.executable_address(function_offset);
            let helper_address = mapping.executable_address(helper_offset);
            let displacement =
                i32::try_from(helper_address as i128 - (function_address + 5) as i128).unwrap();
            let mut code = [0_u8; 9];
            code[0] = 0xE8;
            code[1..5].copy_from_slice(&displacement.to_le_bytes());
            code[5..].copy_from_slice(&[0x83, 0xC0, 0x01, 0xC3]);
            mapping.write(helper_offset, &[0xB8, 41, 0, 0, 0, 0xC3]);
            let hook = install(&mapping, function_offset, &code, 0, record_hook);
            // SAFETY: fixture calls its helper, adds one, and returns u32.
            let function: unsafe extern "C" fn() -> u32 =
                unsafe { core::mem::transmute(function_address as usize) };

            assert_eq!(unsafe { function() }, 42);
            hook.activate().unwrap();
            assert_eq!(unsafe { function() }, 42);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
            hook.deactivate().unwrap();
        }

        #[test]
        fn preserves_live_flags_and_the_system_v_red_zone() {
            let _guard = serial_guard();
            CALLBACKS.store(0, Ordering::Relaxed);
            let flags_mapping = DualMapping::new();
            let flags_offset = 256;
            let flags_code = [
                0x83, 0xFF, 0x00, // cmp edi, 0
                0x0F, 0x1F, 0x44, 0x00, 0x00, // five-byte nop (site)
                0x0F, 0x94, 0xC0, // sete al
                0x0F, 0xB6, 0xC0, // movzx eax, al
                0xC3,
            ];
            let flags_hook = install(
                &flags_mapping,
                flags_offset,
                &flags_code,
                3,
                clobber_flags_hook,
            );
            // SAFETY: fixture is an extern C predicate.
            let predicate: unsafe extern "C" fn(u32) -> u32 = unsafe {
                core::mem::transmute(flags_mapping.executable_address(flags_offset) as usize)
            };
            flags_hook.activate().unwrap();
            assert_eq!(unsafe { predicate(0) }, 1);
            assert_eq!(unsafe { predicate(9) }, 0);
            flags_hook.deactivate().unwrap();

            let red_zone_mapping = DualMapping::new();
            let red_zone_offset = 320;
            let red_zone_code = [
                0x48, 0xC7, 0x44, 0x24, 0xF8, 0x78, 0x56, 0x34, 0x12, 0x0F, 0x1F, 0x44, 0x00, 0x00,
                0x48, 0x8B, 0x44, 0x24, 0xF8, 0xC3,
            ];
            let red_zone_hook = install(
                &red_zone_mapping,
                red_zone_offset,
                &red_zone_code,
                9,
                clobber_flags_hook,
            );
            // SAFETY: fixture is an extern C function returning u64.
            let red_zone: unsafe extern "C" fn() -> u64 = unsafe {
                core::mem::transmute(red_zone_mapping.executable_address(red_zone_offset) as usize)
            };
            red_zone_hook.activate().unwrap();
            assert_eq!(unsafe { red_zone() }, 0x1234_5678);
            red_zone_hook.deactivate().unwrap();
        }

        #[test]
        fn preserves_xmm_argument_across_a_clobbering_callback() {
            let _guard = serial_guard();
            CALLBACKS.store(0, Ordering::Relaxed);
            let mapping = DualMapping::new();
            let offset = 384;
            let code = [0x0F, 0x1F, 0x44, 0x00, 0x00, 0xF2, 0x0F, 0x58, 0xC0, 0xC3];
            let hook = install(&mapping, offset, &code, 0, clobber_xmm_hook);
            // SAFETY: fixture doubles one f64 argument in XMM0.
            let function: unsafe extern "C" fn(f64) -> f64 =
                unsafe { core::mem::transmute(mapping.executable_address(offset) as usize) };
            assert_eq!(unsafe { function(3.25) }, 6.5);
            hook.activate().unwrap();
            assert_eq!(unsafe { function(3.25) }, 6.5);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
            hook.deactivate().unwrap();
        }

        #[test]
        fn preserves_avx_upper_lane_across_a_clobbering_callback() {
            use iced_x86::code_asm::{CodeAssembler, rax, xmm0, ymm1};

            if !std::is_x86_feature_detected!("avx2") {
                return;
            }
            let _guard = serial_guard();
            CALLBACKS.store(0, Ordering::Relaxed);
            let mapping = DualMapping::new();
            let offset = 512;
            let address = mapping.executable_address(offset);
            let mut assembler = CodeAssembler::new(64).unwrap();
            assembler.vpcmpeqd(ymm1, ymm1, ymm1).unwrap();
            assembler.db(&[0x0F, 0x1F, 0x44, 0x00, 0x00]).unwrap();
            assembler.vextracti128(xmm0, ymm1, 1).unwrap();
            assembler.vmovq(rax, xmm0).unwrap();
            assembler.vzeroupper().unwrap();
            assembler.ret().unwrap();
            let code = assembler.assemble(address).unwrap();
            let scan = InstructionScanner::default().scan(&code, address).unwrap();
            let site_offset = scan.instructions()[0].len();
            assert_eq!(scan.instructions()[1].len(), 5);
            let hook = install(&mapping, offset, &code, site_offset, clobber_ymm_hook);
            // SAFETY: fixture returns the high YMM1 lane as u64.
            let function: unsafe extern "C" fn() -> u64 =
                unsafe { core::mem::transmute(address as usize) };

            assert_eq!(unsafe { function() }, u64::MAX);
            hook.activate().unwrap();
            assert_eq!(unsafe { function() }, u64::MAX);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
            hook.deactivate().unwrap();
        }

        #[test]
        fn concurrent_execution_survives_rapid_hook_toggling() {
            let _guard = serial_guard();
            CALLBACKS.store(0, Ordering::Relaxed);
            let mapping = DualMapping::new();
            let offset = 508;
            let code = [0xB8, 7, 0, 0, 0, 0x01, 0xF8, 0xC3];
            let hook = install(&mapping, offset, &code, 0, record_hook);
            let address = mapping.executable_address(offset) as usize;
            let stop = Arc::new(AtomicBool::new(false));
            let start = Arc::new(Barrier::new(5));
            let mut workers = Vec::new();
            for _ in 0..4 {
                let stop = Arc::clone(&stop);
                let start = Arc::clone(&start);
                workers.push(thread::spawn(move || {
                    // SAFETY: process-lifetime fixture implements this signature.
                    let function: unsafe extern "C" fn(u32) -> u32 =
                        unsafe { core::mem::transmute(address) };
                    start.wait();
                    while !stop.load(Ordering::Relaxed) {
                        assert_eq!(unsafe { function(11) }, 18);
                    }
                }));
            }
            start.wait();
            hook.activate().unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while CALLBACKS.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
                thread::yield_now();
            }
            assert!(CALLBACKS.load(Ordering::Relaxed) > 0);
            hook.deactivate().unwrap();
            for _ in 1..1_000 {
                hook.activate().unwrap();
                hook.deactivate().unwrap();
            }
            stop.store(true, Ordering::Relaxed);
            for worker in workers {
                worker.join().unwrap();
            }
        }
    }
}
