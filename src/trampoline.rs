//! Relocation-aware hook trampolines for Linux on x86-64.
//!
//! A trampoline is emitted from one checked plan. It saves the System V AMD64
//! integer context, flags, red zone, and floating-point/SIMD state through AVX-512,
//! calls a hook, restores the context, executes the relocated instruction,
//! and jumps back without clobbering a register. Executable storage is mapped
//! within signed rel32 reach and is never writable through its RX alias.

use core::fmt;
use core::mem::ManuallyDrop;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use core::sync::atomic::compiler_fence;

use iced_x86::BlockEncoder;
use iced_x86::BlockEncoderOptions;
use iced_x86::BlockEncoderResult;
use iced_x86::Code;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Instruction;
use iced_x86::InstructionBlock;
use iced_x86::Mnemonic;
use iced_x86::OpKind;
use iced_x86::RelocKind;
use iced_x86::code_asm::CodeAssembler;
use iced_x86::code_asm::eax;
use iced_x86::code_asm::edx;
use iced_x86::code_asm::qword_ptr;
use iced_x86::code_asm::r8;
use iced_x86::code_asm::r9;
use iced_x86::code_asm::r10;
use iced_x86::code_asm::r11;
use iced_x86::code_asm::r12;
use iced_x86::code_asm::r13;
use iced_x86::code_asm::r14;
use iced_x86::code_asm::r15;
use iced_x86::code_asm::rax;
use iced_x86::code_asm::rbp;
use iced_x86::code_asm::rbx;
use iced_x86::code_asm::rcx;
use iced_x86::code_asm::rdi;
use iced_x86::code_asm::rdx;
use iced_x86::code_asm::rsi;
use iced_x86::code_asm::rsp;

use crate::artifact_fixups::{
    self as fixups, BiasDomain, Encoding, Fixup, ImageId, ImagePlacement, RelativeAddress, Role,
    Target,
};
use crate::artifact_fragments;
use crate::controls::{ControlledAction, ProbeControl};
use crate::emission::{
    ArtifactEmission, ArtifactField, ArtifactFieldEncoding, ArtifactImageMetadata,
    ArtifactRequirement,
};
use crate::frame_trace::{
    FrameCallKind, FrameEffect, FrameEmission, FrameEntryOrigin, FrameRecorder, FrameStage,
    FrameTraceLimits, FrameTraceRefusal, HelperFrames,
};
use crate::patcher::JumpPatchPlan;
use crate::patcher::LiveJumpPatch;
use crate::patcher::PatchError;
use crate::patcher::StalenessBudget;
use crate::scanner::InstructionScanner;
use crate::scanner::ScanResult;

const SYSTEM_V_RED_ZONE_BYTES: i32 = 128;
const SAVED_INTEGER_BYTES: i32 = 16 * 8;
const HOOK_METADATA_BYTES: i32 = 2 * 8;
const SAVED_EXTENDED_STATE_DESCRIPTOR_BYTES: i32 = 4 * 8;
const FXSAVE_BYTES: i32 = 512;
const FXSAVE_ALIGNMENT: i32 = 16;
/// Bytes below entry RSP occupied before the extended-state save allocation.
///
/// For ptrace-owned stacks, the HookContext base (live R12) is exactly this far
/// below the controller-supplied stack top.
pub const HOOK_CONTEXT_STACK_PREFIX_BYTES: usize = (SYSTEM_V_RED_ZONE_BYTES
    + SAVED_EXTENDED_STATE_DESCRIPTOR_BYTES
    + SAVED_INTEGER_BYTES
    + HOOK_METADATA_BYTES) as usize;
const _: () = assert!(HOOK_CONTEXT_STACK_PREFIX_BYTES == 304);
/// Maximum non-legacy xfeatures described by one emitted trampoline.
///
/// The current preservation mask has five such bits. Keeping spare entries
/// permits conservative growth while construction still fails rather than
/// truncating whenever an exact mask cannot fit.
pub const SAVED_EXTENDED_STATE_COMPONENT_CAPACITY: usize = 8;
const NEAR_RETURN_JUMP_BYTES: usize = 5;
const NOTRACK_ABSOLUTE_JUMP_BYTES: usize = 15;
const BRANCH_RELAY_CODE: [u8; 11] = [0xf3, 0x0f, 0x1e, 0xfa, 0x3e, 0xff, 0x25, 0, 0, 0, 0];
const BRANCH_RELAY_BYTES: usize = BRANCH_RELAY_CODE.len() + core::mem::size_of::<u64>();
const PTRACE_STOP_BYTES: [u8; 1] = [0xcc];
const PRESERVED_USER_STATE_MASK: u64 = 0b10_1110_0111;
const PKRU_XFEATURE: u64 = 1 << 9;
const TRAMPOLINE_ALLOCATION_BYTES: usize = 4096;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const MAX_PROCESS_MAPS_BYTES: usize = 2 * 1024 * 1024;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const MIN_PROCESS_MAP_RECORD_BYTES: usize = 40;

const STATE_INACTIVE: u8 = 0;
const STATE_ACTIVE: u8 = 1;
const STATE_TRANSITIONING: u8 = 2;

/// Stable wire tag describing the instruction that produced a saved state area.
///
/// This is a transparent integer rather than a Rust enum because the descriptor
/// crosses an instrumentation/controller memory boundary. Every bit pattern is
/// therefore safe to read; consumers must admit only the named constants.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SavedExtendedStateFormat(u64);

impl SavedExtendedStateFormat {
    /// No saved extended-state image is available.
    pub const UNAVAILABLE: Self = Self(0);
    /// Legacy 512-byte `FXSAVE64` image aligned to 16 bytes.
    pub const FXSAVE64: Self = Self(1);
    /// Standard, non-compacted `XSAVE64` image aligned to 64 bytes.
    pub const XSAVE64_STANDARD: Self = Self(2);

    /// Returns the stable integer carried by the cross-process ABI.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Returns the required saved-area alignment for an admitted format.
    pub const fn required_alignment(self) -> Option<u64> {
        if self.0 == Self::FXSAVE64.0 {
            Some(FXSAVE_ALIGNMENT as u64)
        } else if self.0 == Self::XSAVE64_STANDARD.0 {
            Some(64)
        } else {
            None
        }
    }
}

/// One standard-format XSAVE component selected by a trampoline.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SavedExtendedStateComponent {
    xfeature: u64,
    offset: u64,
    size: u64,
}

impl SavedExtendedStateComponent {
    const UNAVAILABLE: Self = Self {
        xfeature: 0,
        offset: 0,
        size: 0,
    };

    const fn new(xfeature: u64, offset: u64, size: u64) -> Self {
        Self {
            xfeature,
            offset,
            size,
        }
    }

    /// Returns the one-hot xfeature bit represented by this entry.
    pub const fn xfeature(self) -> u64 {
        self.xfeature
    }

    /// Returns the component's offset in a standard XSAVE image.
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Returns the component's architectural byte length.
    pub const fn size(self) -> u64 {
        self.size
    }
}

/// Per-trampoline extended-state save layout and authenticated component map.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SavedExtendedStateLayout {
    allocation_len: u64,
    image_len: u64,
    mask: u64,
    format: SavedExtendedStateFormat,
    component_count: u64,
    components: [SavedExtendedStateComponent; SAVED_EXTENDED_STATE_COMPONENT_CAPACITY],
}

impl SavedExtendedStateLayout {
    /// Explicit absence used by contexts that did not originate in a trampoline.
    pub const UNAVAILABLE: Self = Self {
        allocation_len: 0,
        image_len: 0,
        mask: 0,
        format: SavedExtendedStateFormat::UNAVAILABLE,
        component_count: 0,
        components: [SavedExtendedStateComponent::UNAVAILABLE;
            SAVED_EXTENDED_STATE_COMPONENT_CAPACITY],
    };

    const FXSAVE64: Self = Self {
        allocation_len: FXSAVE_BYTES as u64,
        image_len: FXSAVE_BYTES as u64,
        mask: 0b11,
        format: SavedExtendedStateFormat::FXSAVE64,
        component_count: 0,
        components: [SavedExtendedStateComponent::UNAVAILABLE;
            SAVED_EXTENDED_STATE_COMPONENT_CAPACITY],
    };

    const fn standard_xsave64(
        allocation_len: u64,
        image_len: u64,
        mask: u64,
        component_count: u64,
        components: [SavedExtendedStateComponent; SAVED_EXTENDED_STATE_COMPONENT_CAPACITY],
    ) -> Self {
        Self {
            allocation_len,
            image_len,
            mask,
            format: SavedExtendedStateFormat::XSAVE64_STANDARD,
            component_count,
            components,
        }
    }

    /// Declares the legacy 512-byte target save layout without querying this CPU.
    /// The eventual execution environment must independently qualify this ISA
    /// and the absence of additional application state requiring preservation.
    pub const fn describe_target_fxsave64() -> Self {
        Self::FXSAVE64
    }

    /// Checks a supplied standard XSAVE target layout without CPUID/XGETBV.
    /// Tuples are `(one_hot_xfeature, byte_offset, byte_size)` for every selected
    /// non-legacy user component, in increasing feature order. This authenticates
    /// shape only; exact target CPU/XCR0/permissions remain an admission duty.
    pub fn describe_target_xsave64(
        mask: u64,
        supplied: &[(u64, u64, u64)],
    ) -> Result<Self, TrampolineError> {
        let invalid = |message| TrampolineError::InvalidExtendedStateLayout { message };
        if mask & 0b11 != 0b11 || mask & !PRESERVED_USER_STATE_MASK != 0 {
            return Err(invalid(
                "declared target mask is outside the current preserved-state envelope",
            ));
        }
        let avx512 = (1 << 5) | (1 << 6) | (1 << 7);
        if mask & avx512 != 0 && mask & (avx512 | (1 << 2)) != (avx512 | (1 << 2)) {
            return Err(invalid(
                "declared target AVX-512 mask lacks architectural dependencies",
            ));
        }
        if supplied.len() > SAVED_EXTENDED_STATE_COMPONENT_CAPACITY {
            return Err(invalid(
                "declared target component capacity is insufficient",
            ));
        }
        let mut components =
            [SavedExtendedStateComponent::UNAVAILABLE; SAVED_EXTENDED_STATE_COMPONENT_CAPACITY];
        let mut seen = 0b11;
        let mut last = 2;
        let mut image_len = 576_u64;
        for (index, &(feature, offset, size)) in supplied.iter().enumerate() {
            if !feature.is_power_of_two()
                || feature <= last
                || mask & feature == 0
                || size == 0
                || offset < 576
            {
                return Err(invalid(
                    "declared target component identity or extent is invalid",
                ));
            }
            let end = offset
                .checked_add(size)
                .ok_or_else(|| invalid("declared target component extent overflows"))?;
            if components[..index]
                .iter()
                .any(|prior| offset < prior.offset + prior.size && prior.offset < end)
            {
                return Err(invalid("declared target component extents overlap"));
            }
            if feature == PKRU_XFEATURE && size < 8 {
                return Err(invalid(
                    "declared PKRU component cannot hold its reserved word",
                ));
            }
            components[index] = SavedExtendedStateComponent::new(feature, offset, size);
            seen |= feature;
            last = feature;
            image_len = image_len.max(end);
        }
        if seen != mask {
            return Err(invalid("declared target component table is incomplete"));
        }
        let allocation = image_len
            .checked_add(63)
            .map(|len| len & !63)
            .and_then(|len| i32::try_from(len).ok())
            .ok_or_else(|| invalid("declared target save allocation is not representable"))?;
        Ok(Self::standard_xsave64(
            allocation as u64,
            image_len,
            mask,
            supplied.len() as u64,
            components,
        ))
    }

    /// Returns the allocated saved-area length.
    pub const fn len(self) -> u64 {
        self.allocation_len
    }

    /// Returns whether no saved extended-state image is available.
    pub const fn is_empty(self) -> bool {
        self.allocation_len == 0
    }

    /// Returns the logical standard-image extent before allocation padding.
    pub const fn image_len(self) -> u64 {
        self.image_len
    }

    /// Returns the exact mask supplied to `XSAVE64`/`XRSTOR64`.
    ///
    /// `FXSAVE64` uses the architectural x87/SSE mask `0b11`.
    pub const fn mask(self) -> u64 {
        self.mask
    }

    /// Returns the stable saved-image format tag.
    pub const fn format(self) -> SavedExtendedStateFormat {
        self.format
    }

    /// Returns the exact non-legacy standard-format component table.
    pub fn components(&self) -> &[SavedExtendedStateComponent] {
        &self.components[..self.component_count as usize]
    }
}

/// One invocation's saved extended-state image.
///
/// The first field is the actual address established by the emitted alignment
/// and allocation instructions. The remaining fields must exactly equal the
/// layout published for the trampoline that supplied the enclosing context.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SavedExtendedStateDescriptor {
    address: u64,
    len: u64,
    mask: u64,
    format: SavedExtendedStateFormat,
}

impl SavedExtendedStateDescriptor {
    /// Explicit absence used by contexts that did not originate in a trampoline.
    pub const UNAVAILABLE: Self = Self {
        address: 0,
        len: 0,
        mask: 0,
        format: SavedExtendedStateFormat::UNAVAILABLE,
    };

    /// Returns the saved area's tracee virtual address.
    pub const fn address(self) -> u64 {
        self.address
    }

    /// Returns the allocated saved-area length.
    pub const fn len(self) -> u64 {
        self.len
    }

    /// Returns whether this descriptor carries no saved image.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns the exact mask supplied to `XSAVE64`/`XRSTOR64`.
    pub const fn mask(self) -> u64 {
        self.mask
    }

    /// Returns the stable saved-image format tag.
    pub const fn format(self) -> SavedExtendedStateFormat {
        self.format
    }

    /// Checks the descriptor fields that are repeated in an authenticated layout.
    pub fn matches_layout(self, layout: SavedExtendedStateLayout) -> bool {
        self.len == layout.len() && self.mask == layout.mask() && self.format == layout.format()
    }
}

const _: () = assert!(core::mem::size_of::<SavedExtendedStateFormat>() == 8);
const _: () = assert!(core::mem::size_of::<SavedExtendedStateComponent>() == 24);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateComponent, xfeature) == 0);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateComponent, offset) == 8);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateComponent, size) == 16);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateLayout, allocation_len) == 0);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateLayout, image_len) == 8);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateLayout, mask) == 16);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateLayout, format) == 24);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateLayout, component_count) == 32);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateLayout, components) == 40);
const _: () = assert!(core::mem::size_of::<SavedExtendedStateLayout>() == 232);
const _: () = assert!(core::mem::size_of::<SavedExtendedStateDescriptor>() == 32);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateDescriptor, address) == 0);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateDescriptor, len) == 8);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateDescriptor, mask) == 16);
const _: () = assert!(core::mem::offset_of!(SavedExtendedStateDescriptor, format) == 24);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SavedExtendedStateLayout {
    /// Detects the exact tracee-side layout used by patch-window trampolines.
    ///
    /// Runtime stack sizing and trampoline emission share this single CPUID/
    /// XGETBV implementation. Callers must still require exact equality before
    /// publishing a hook in case the per-thread enabled state changed.
    pub fn detect() -> Result<Self, TrampolineError> {
        Self::detect_with_mask(PRESERVED_USER_STATE_MASK)
    }

    #[allow(unused_unsafe)]
    fn detect_with_mask(preservation_mask: u64) -> Result<Self, TrampolineError> {
        use core::arch::x86_64::__cpuid;
        use core::arch::x86_64::__cpuid_count;
        use core::arch::x86_64::_xgetbv;

        // SAFETY: CPUID is available in x86-64 mode.
        let features = unsafe { __cpuid(1) };
        let has_xsave = features.ecx & (1 << 26) != 0;
        let has_osxsave = features.ecx & (1 << 27) != 0;
        if !has_xsave || !has_osxsave {
            return Ok(Self::FXSAVE64);
        }

        // SAFETY: OSXSAVE proves XGETBV is enabled for XCR0. Linux can expose
        // AMX in XCR0 while denying this thread tile-state permission through
        // XFD. Preserve the universally usable user components through PKRU
        // and leave AMX to its explicit owner.
        let mask = unsafe { _xgetbv(0) } & preservation_mask;
        let root = unsafe { __cpuid_count(0xD, 0) };
        let supported = u64::from(root.eax) | (u64::from(root.edx) << 32);
        if mask & 0b11 != 0b11 || mask & !supported != 0 {
            return Err(TrampolineError::InvalidExtendedStateLayout {
                message: "XCR0 preservation mask is incomplete or unsupported",
            });
        }

        let mut components =
            [SavedExtendedStateComponent::UNAVAILABLE; SAVED_EXTENDED_STATE_COMPONENT_CAPACITY];
        let mut component_count = 0_usize;
        let mut image_len = 576_u64;
        for index in 2..64_u32 {
            let xfeature = 1_u64 << index;
            if mask & xfeature == 0 {
                continue;
            }
            if component_count == components.len() {
                return Err(TrampolineError::InvalidExtendedStateLayout {
                    message: "XSAVE component table capacity is insufficient",
                });
            }
            let leaf = unsafe { __cpuid_count(0xD, index) };
            let offset = u64::from(leaf.ebx);
            let size = u64::from(leaf.eax);
            let Some(end) = offset.checked_add(size) else {
                return Err(TrampolineError::InvalidExtendedStateLayout {
                    message: "XSAVE component extent overflows",
                });
            };
            if size == 0 || offset < 576 || leaf.ecx & 1 != 0 {
                return Err(TrampolineError::InvalidExtendedStateLayout {
                    message: "XSAVE component lacks a standard user-state layout",
                });
            }
            if components[..component_count].iter().any(|component| {
                let prior_end = component.offset + component.size;
                offset < prior_end && component.offset < end
            }) {
                return Err(TrampolineError::InvalidExtendedStateLayout {
                    message: "XSAVE component extents overlap",
                });
            }
            components[component_count] = SavedExtendedStateComponent::new(xfeature, offset, size);
            component_count += 1;
            image_len = image_len.max(end);
        }
        let allocation_len = image_len
            .checked_add(63)
            .map(|value| value & !63)
            .and_then(|value| i32::try_from(value).ok())
            .filter(|value| *value >= 576)
            .ok_or(TrampolineError::InvalidExtendedStateLayout {
                message: "XSAVE image allocation is not representable",
            })?;
        Ok(Self::standard_xsave64(
            allocation_len as u64,
            image_len,
            mask,
            component_count as u64,
            components,
        ))
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SavedExtendedStateLayout {
    fn encode_save(&self, assembler: &mut CodeAssembler) -> Result<(), TrampolineError> {
        let (alignment, bytes) = if self.format() == SavedExtendedStateFormat::FXSAVE64 {
            (FXSAVE_ALIGNMENT, FXSAVE_BYTES)
        } else if self.format() == SavedExtendedStateFormat::XSAVE64_STANDARD {
            let bytes = i32::try_from(self.len()).map_err(|_| {
                TrampolineError::InvalidExtendedStateLayout {
                    message: "XSAVE allocation length is not representable",
                }
            })?;
            (64, bytes)
        } else {
            return Err(TrampolineError::InvalidExtendedStateLayout {
                message: "saved-state format is unavailable",
            });
        };
        assembler.and(rsp, -alignment).map_err(encoding_error)?;
        assembler.sub(rsp, bytes).map_err(encoding_error)?;
        if self.format() == SavedExtendedStateFormat::FXSAVE64 {
            assembler.fxsave64(rsp.into()).map_err(encoding_error)
        } else {
            let mask = self.mask();
            // XSAVE does not initialize every reserved header byte, while
            // XRSTOR requires them to be zero or raises #GP.
            assembler.xor(eax, eax).map_err(encoding_error)?;
            for offset in (512..576).step_by(8) {
                assembler
                    .mov(qword_ptr(rsp + offset), rax)
                    .map_err(encoding_error)?;
            }
            if mask & PKRU_XFEATURE != 0 {
                let invalid = || TrampolineError::InvalidExtendedStateLayout {
                    message: "saved PKRU reserved word has an invalid extent",
                };
                let component = self
                    .components()
                    .iter()
                    .find(|component| component.xfeature() == PKRU_XFEATURE)
                    .ok_or_else(invalid)?;
                let end = component.offset().checked_add(8).ok_or_else(invalid)?;
                if component.size() != 8
                    || component.offset() < 576
                    || component.offset() % 8 != 0
                    || end > self.image_len()
                    || end > self.len()
                {
                    return Err(invalid());
                }
                let upper = i32::try_from(end - 4).map_err(|_| invalid())?;
                // Own the reserved-word initialization before a callback can
                // inspect it; the component extent alone is not that proof.
                assembler
                    .mov(iced_x86::code_asm::dword_ptr(rsp + upper), eax)
                    .map_err(encoding_error)?;
            }
            assembler.mov(eax, mask as u32).map_err(encoding_error)?;
            assembler
                .mov(edx, (mask >> 32) as u32)
                .map_err(encoding_error)?;
            assembler.xsave64(rsp.into()).map_err(encoding_error)
        }
    }

    fn encode_restore(&self, assembler: &mut CodeAssembler) -> Result<(), TrampolineError> {
        if self.format() == SavedExtendedStateFormat::FXSAVE64 {
            assembler.fxrstor64(rsp.into()).map_err(encoding_error)
        } else if self.format() == SavedExtendedStateFormat::XSAVE64_STANDARD {
            let mask = self.mask();
            assembler.mov(eax, mask as u32).map_err(encoding_error)?;
            assembler
                .mov(edx, (mask >> 32) as u32)
                .map_err(encoding_error)?;
            assembler.xrstor64(rsp.into()).map_err(encoding_error)
        } else {
            Err(TrampolineError::InvalidExtendedStateLayout {
                message: "saved-state format is unavailable",
            })
        }
    }
}

/// Callback invoked before the displaced application instruction.
///
/// The context remains valid only for the callback. The callback must follow
/// the System V AMD64 ABI and must not unwind through generated machine code.
/// Patch-window plans preserve x87 through AVX-512 plus PKRU. An exact-syscall
/// plan preserves the same floating-point/SIMD state but leaves live PKRU
/// unchanged on return; its saved-state descriptor excludes PKRU. Callbacks
/// must not modify permission-gated AMX or other extended state outside that
/// contract.
pub type HookCallback = unsafe extern "C" fn(*mut HookContext);

/// Mutable integer-register snapshot at the instrumented instruction.
///
/// Callback changes to saved GPRs and RFLAGS are restored into application
/// state. The instruction and stack-pointer fields are metadata. SIMD state is
/// preserved transparently rather than exposed to callbacks.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
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
    /// Trampoline-owned descriptor for the saved extended-state image.
    ///
    /// Callbacks must treat this as read-only. Contexts synthesized outside a
    /// generated trampoline report [`SavedExtendedStateDescriptor::UNAVAILABLE`].
    saved_extended_state: SavedExtendedStateDescriptor,
}

impl HookContext {
    /// Returns the generated trampoline's per-invocation saved-state descriptor.
    pub const fn saved_extended_state(&self) -> SavedExtendedStateDescriptor {
        self.saved_extended_state
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod backedge_clock;
mod original_nops;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod saved_pkru;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use saved_pkru::SavedPkruView;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "saved-pkru-probe"
))]
pub use saved_pkru::run_saved_pkru_physical_probe;

const _: () = assert!(core::mem::offset_of!(HookContext, instruction_pointer) == 0);
const _: () = assert!(core::mem::offset_of!(HookContext, rflags) == 136);
const _: () = assert!(core::mem::offset_of!(HookContext, saved_extended_state) == 144);
const _: () = assert!(core::mem::size_of::<HookContext>() == 176);

/// Checked byte lengths and saved-state layout for one trampoline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrampolineLayout {
    /// Original instructions executed before the first logical hook.
    ///
    /// This is zero for the original same-site constructors.
    pub relocated_prefix_len: usize,
    /// Optional INT3 reached with the untouched application register state.
    pub entry_stop_len: usize,
    /// Context-save and instrumentation-call bytes for the first logical hook.
    pub instrumentation_len: usize,
    /// Optional INT3 reached after the complete application-state restore.
    pub completion_stop_len: usize,
    /// Relocated instructions, including any jump over encoder padding and literals.
    /// Coalesced images also include subsequent hook/restore groups here; the
    /// instrumentation and restore lengths describe the first logical hook.
    pub relocated_len: usize,
    /// Context-restore bytes for the first logical hook.
    pub restore_len: usize,
    /// Control-transfer bytes returning to application code.
    pub return_len: usize,
    /// Exact format, allocation length, and mask used for extended state.
    pub saved_extended_state: SavedExtendedStateLayout,
}

impl TrampolineLayout {
    /// Returns the total allocation size, or None if the sum overflows.
    pub fn total_len(self) -> Option<usize> {
        self.relocated_prefix_len
            .checked_add(self.entry_stop_len)?
            .checked_add(self.instrumentation_len)?
            .checked_add(self.restore_len)?
            .checked_add(self.completion_stop_len)?
            .checked_add(self.relocated_len)?
            .checked_add(self.return_len)
    }
}

/// Complete emitted bytes and section boundaries for a trampoline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrampolineImage {
    address: u64,
    bytes: Vec<u8>,
    layout: TrampolineLayout,
    program_counters: Vec<ProgramCounterMapping>,
    entry_routes: Vec<(u64, u64)>,
    instruction_boundaries: Vec<(u64, u64)>,
    controls: Vec<ProbeControl>,
    clock: Option<crate::backedge_clock::BackedgeClock>,
    clock_gate: Option<crate::backedge_clock::ClockGateLayout>,
    artifact: Option<ArtifactImageMetadata>,
}

impl TrampolineImage {
    pub(crate) fn artifact_metadata(&self) -> Option<&ArtifactImageMetadata> {
        self.artifact.as_ref()
    }
    pub(crate) fn require_artifact_router(&mut self) {
        if let Some(metadata) = self.artifact.as_mut() {
            if !metadata
                .requirements
                .contains(&ArtifactRequirement::EntryRouterBootstrap)
            {
                metadata
                    .requirements
                    .push(ArtifactRequirement::EntryRouterBootstrap);
            }
        }
    }

    /// Returns the exact executable address used to encode this image.
    pub const fn address(&self) -> u64 {
        self.address
    }

    /// Returns the emitted machine code.
    ///
    /// Controlled images embed pointers to their retained control blocks. A
    /// custom executable allocator copying these bytes must retain every
    /// control and any `clock()` owner for the entire executable-code lifetime.
    /// The provided private
    /// and grouped allocators retain those references automatically.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Stable observing controls retained by this immutable image.
    ///
    /// Controls occupy separate mutable data, not immutable code backing.
    /// Their payload size excludes Arc and allocator overhead.
    pub fn controls(&self) -> &[ProbeControl] {
        &self.controls
    }

    /// Exact inline gate boundaries, present only for the finite clock profile.
    pub fn clock_gate(&self) -> Option<crate::backedge_clock::ClockGateLayout> {
        self.clock_gate
    }

    /// Retained separate RW owner for a finite clock image.
    pub fn clock(&self) -> Option<&crate::backedge_clock::BackedgeClock> {
        self.clock.as_ref()
    }

    /// Returns the checked section lengths.
    pub const fn layout(&self) -> TrampolineLayout {
        self.layout
    }

    /// Returns executable ranges and their corresponding application PCs.
    /// Encoder padding and literal data have no application PC mapping.
    pub fn program_counter_mappings(&self) -> &[ProgramCounterMapping] {
        &self.program_counters
    }

    /// Returns original instruction heads and their generated entry addresses.
    ///
    /// Entering a logical hook's route executes its callback. Entering a
    /// later head bypasses earlier hooks, while an upstream entry executes the
    /// remaining prefix before reaching them. These routes are distinct from the
    /// reverse-PC ranges used to report faults in instrumentation code.
    /// The explicit inline-clock profile enters its gate; only a zero boundary
    /// in Stop mode enters the callback. Counter mode never invokes it.
    pub fn entry_routes(&self) -> &[(u64, u64)] {
        &self.entry_routes
    }

    /// Returns original heads and generated PCs immediately before execution.
    ///
    /// The application register and extended state has been restored at these
    /// boundaries. The hook's own entry is not a comparison boundary; an
    /// observing logical instruction has its boundary after the restore.
    /// Replaced instructions have an entry route but no execution boundary.
    pub fn instruction_boundaries(&self) -> &[(u64, u64)] {
        &self.instruction_boundaries
    }
}

/// One half-open generated-code range and its logical application PC.
///
/// A signal handler or unwind front end can translate a PC in this range before
/// reporting or unwinding it. The mapping does not itself install a signal
/// handler or provide call-frame information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramCounterMapping {
    generated_start: u64,
    generated_end: u64,
    logical_address: u64,
}

impl ProgramCounterMapping {
    /// Returns the first generated PC in this mapping.
    pub const fn generated_start(&self) -> u64 {
        self.generated_start
    }

    /// Returns the first generated PC after this mapping.
    pub const fn generated_end(&self) -> u64 {
        self.generated_end
    }

    /// Returns the application PC represented by this generated range.
    pub const fn logical_address(&self) -> u64 {
        self.logical_address
    }

    /// Translates a generated PC covered by this mapping.
    pub const fn translate(&self, program_counter: u64) -> Option<u64> {
        if self.generated_start <= program_counter && program_counter < self.generated_end {
            Some(self.logical_address)
        } else {
            None
        }
    }
}

struct ProgramCounterMapNode {
    mappings: Box<[ProgramCounterMapping]>,
    next: *mut ProgramCounterMapNode,
}

static PROGRAM_COUNTER_MAP_HEAD: AtomicPtr<ProgramCounterMapNode> =
    AtomicPtr::new(core::ptr::null_mut());

/// Translates a PC in a published trampoline to its application instruction.
///
/// Published mappings live for the process lifetime. This lookup performs only
/// atomic loads and immutable reads, so it can be called from a signal handler.
/// Returning `None` means the PC is not in a published executable range;
/// trampoline padding and literal data are not executable ranges.
pub fn translate_program_counter(program_counter: u64) -> Option<u64> {
    let mut node = PROGRAM_COUNTER_MAP_HEAD.load(Ordering::Acquire);
    while !node.is_null() {
        // SAFETY: nodes and their mapping arrays are leaked after publication.
        let published = unsafe { &*node };
        for mapping in &published.mappings {
            if let Some(logical_address) = mapping.translate(program_counter) {
                return Some(logical_address);
            }
        }
        node = published.next;
    }
    None
}

fn register_program_counter_mappings(mappings: &[ProgramCounterMapping]) {
    let node = Box::into_raw(Box::new(ProgramCounterMapNode {
        mappings: mappings.to_vec().into_boxed_slice(),
        next: core::ptr::null_mut(),
    }));
    let mut head = PROGRAM_COUNTER_MAP_HEAD.load(Ordering::Acquire);
    loop {
        // SAFETY: node is private to this publisher until the release CAS.
        unsafe { (*node).next = head };
        match PROGRAM_COUNTER_MAP_HEAD.compare_exchange_weak(
            head,
            node,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(observed) => head = observed,
        }
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
    /// The exact-syscall plan requires the literal two-byte `0F 05` instruction.
    NotExactSyscall {
        /// Requested instruction address.
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
    /// Provisional artifact emission failed a field/provenance/PIC obligation.
    Artifact {
        /// Stable reason category; no executable-artifact success is implied.
        reason: crate::emission::ArtifactRefusalKind,
        /// Exact encoder/field diagnostic.
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
    /// The exact instruction-pun destination is already occupied or unavailable.
    ExactAddressUnavailable {
        /// Required trampoline entry address.
        address: u64,
    },
    /// A trampoline arena must contain at least one checked slot.
    InvalidArenaCapacity,
    /// Process-local observing controls cannot be stored in a fork-shared arena.
    ControlledArenaUnsupported,
    /// Every slot in a prepared trampoline arena has been reserved.
    ArenaFull,
    /// Emitted code does not fit in its executable allocation.
    CodeTooLarge {
        /// Emitted code bytes.
        code_len: usize,
        /// Available allocation bytes.
        allocation_len: usize,
    },
    /// The tracee CPU's enabled standard XSAVE layout cannot be encoded exactly.
    InvalidExtendedStateLayout {
        /// Fail-closed layout diagnostic.
        message: &'static str,
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
            Self::NotExactSyscall {
                address,
                instruction_len,
            } => write!(
                formatter,
                "instruction at {address:#x} with length {instruction_len} is not the literal two-byte syscall 0F 05"
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
            Self::Artifact { reason, message } => write!(formatter, "artifact {reason:?}: {message}"),
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
            Self::ExactAddressUnavailable { address } => {
                write!(
                    formatter,
                    "exact trampoline address {address:#x} is unavailable"
                )
            }
            Self::InvalidArenaCapacity => {
                formatter.write_str("trampoline arena capacity must be non-zero")
            }
            Self::ControlledArenaUnsupported => formatter.write_str(
                "runtime observing controls require private or sealed-grouped mappings; shared arenas are unsupported",
            ),
            Self::ArenaFull => formatter.write_str("trampoline arena has no free slots"),
            Self::CodeTooLarge {
                code_len,
                allocation_len,
            } => write!(
                formatter,
                "{code_len}-byte trampoline exceeds {allocation_len}-byte allocation"
            ),
            Self::InvalidExtendedStateLayout { message } => {
                write!(formatter, "invalid extended-state layout: {message}")
            }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrampolineKind {
    PatchWindow,
    ExactSyscall,
    Instruction,
    Actions,
}

/// Immutable emission plan for logical hooks or callback-free relocation.
#[derive(Clone, Debug)]
pub struct TrampolinePlan {
    execute_address: u64,
    return_address: u64,
    hook: Option<HookCallback>,
    actions: Vec<(u64, HookCallback, bool)>,
    controls: Vec<ControlledAction>,
    clock: Option<Box<crate::backedge_clock::BackedgeClockAction>>,
    instructions: Vec<Instruction>,
    source_nops: Vec<Option<Vec<u8>>>,
    logical_index: usize,
    relocated_start: usize,
    ptrace_stops: bool,
    kind: TrampolineKind,
}

impl TrampolinePlan {
    /// Builds an observing plan from an instruction scan.
    ///
    /// Complete consecutive instructions are displaced until their combined
    /// length can contain a five-byte near jump. The hook runs before all
    /// displaced instructions are relocated and executed, including each
    /// direct backedge to the instrumented entry.
    pub fn from_scan(
        scan: &ScanResult,
        execute_address: u64,
        hook: HookCallback,
    ) -> Result<Self, TrampolineError> {
        Self::from_scan_mode(scan, execute_address, hook, 0, false)
    }

    /// Builds a plan whose hook replaces the first displaced instruction.
    ///
    /// Instructions after the first one are still relocated and executed.
    /// This supports short operations such as the two-byte x86-64 syscall:
    /// the hook emulates the operation, the trampoline executes any tail
    /// instructions consumed by the five-byte patch, and control resumes after
    /// the complete displaced window.
    pub fn from_scan_replacing_first(
        scan: &ScanResult,
        execute_address: u64,
        hook: HookCallback,
    ) -> Result<Self, TrampolineError> {
        Self::from_scan_mode(scan, execute_address, hook, 1, false)
    }

    /// Builds a standalone plan replacing only a literal two-byte `0F 05`.
    ///
    /// The scanned instruction must be an unprefixed native x86-64 `SYSCALL`.
    /// The hook replaces it, no following application instructions are copied,
    /// and a register- and flag-neutral jump resumes at `execute_address + 2`.
    /// This constructor does not satisfy the five-byte patch-window contract;
    /// callers must arrange entry separately, without treating it as a plan for
    /// a live jump patch. Planning, emission, and arena allocation leave the
    /// source bytes unchanged.
    ///
    /// Unlike the patch-window constructors, this plan excludes PKRU from both
    /// XSAVE and XRSTOR. The saved-state layout, component map, and callback
    /// descriptor describe that exact mask. Live rights established during the
    /// callback (including by a genuine signal return) therefore survive the
    /// trampoline return. All other supported floating-point/SIMD state and
    /// the ordinary GPR, RFLAGS, RSP, and red-zone contract remain unchanged.
    /// Capture and callback execution still use the incoming stack; this is
    /// not an owned-stack or memory-protection boundary.
    pub fn from_scan_replacing_exact_syscall(
        scan: &ScanResult,
        execute_address: u64,
        hook: HookCallback,
    ) -> Result<Self, TrampolineError> {
        let scanned = scan
            .instructions()
            .iter()
            .find(|instruction| instruction.address() == execute_address)
            .ok_or(TrampolineError::SiteNotFound {
                address: execute_address,
            })?;
        let bytes = scanned
            .offset()
            .checked_add(2)
            .and_then(|end| scan.snapshot().get(scanned.offset()..end));
        if scanned.instruction().code() != Code::Syscall
            || scanned.len() != 2
            || bytes != Some([0x0f, 0x05].as_slice())
        {
            return Err(TrampolineError::NotExactSyscall {
                address: execute_address,
                instruction_len: scanned.len(),
            });
        }
        let return_address =
            execute_address
                .checked_add(2)
                .ok_or(TrampolineError::ReturnAddressOverflow {
                    address: execute_address,
                    instruction_len: 2,
                })?;
        Ok(Self {
            execute_address,
            return_address,
            hook: Some(hook),
            actions: Vec::new(),
            controls: Vec::new(),
            clock: None,
            source_nops: original_nops::capture(scan, &[*scanned.instruction()])?,
            instructions: vec![*scanned.instruction()],
            logical_index: 0,
            relocated_start: 1,
            ptrace_stops: false,
            kind: TrampolineKind::ExactSyscall,
        })
    }

    /// Builds a replace-first plan bracketed by two tracer-owned INT3 stops.
    ///
    /// The entry stop executes before any instrumentation code with the
    /// application register file untouched. Before suppressing it, the external
    /// ptrace controller must write the application RSP at `owned_top - 8` and
    /// replace RSP with `owned_top`, where the complete downward-growing owned
    /// stack is controller-authenticated. Instrumentation then saves and calls
    /// entirely on that owned stack while retaining the application RSP in
    /// [`HookContext`]. At the completion stop every explicitly saved GPR,
    /// RFLAGS, and extended-state component has been restored. RSP deliberately
    /// remains `owned_top`; the authenticated controller must restore the
    /// application RSP before exposing the relocated tail. Executing this mode
    /// without a controller that performs both pivots is unsupported.
    pub fn from_scan_replacing_first_with_ptrace_stops(
        scan: &ScanResult,
        execute_address: u64,
        hook: HookCallback,
    ) -> Result<Self, TrampolineError> {
        Self::from_scan_mode(scan, execute_address, hook, 1, true)
    }

    fn from_scan_mode(
        scan: &ScanResult,
        execute_address: u64,
        hook: HookCallback,
        relocated_start: usize,
        ptrace_stops: bool,
    ) -> Result<Self, TrampolineError> {
        let start_index = scan
            .instructions()
            .iter()
            .position(|instruction| instruction.address() == execute_address)
            .ok_or(TrampolineError::SiteNotFound {
                address: execute_address,
            })?;
        let mut displaced_len = 0_usize;
        let mut instructions = Vec::new();
        for scanned in &scan.instructions()[start_index..] {
            let expected = execute_address.checked_add(displaced_len as u64).ok_or(
                TrampolineError::ReturnAddressOverflow {
                    address: execute_address,
                    instruction_len: displaced_len,
                },
            )?;
            if scanned.address() != expected {
                break;
            }
            displaced_len = displaced_len.checked_add(scanned.len()).ok_or(
                TrampolineError::ReturnAddressOverflow {
                    address: execute_address,
                    instruction_len: displaced_len,
                },
            )?;
            instructions.push(scanned.instruction().to_owned());
            if displaced_len >= crate::patcher::NEAR_JUMP_BYTES {
                break;
            }
        }
        if displaced_len < crate::patcher::NEAR_JUMP_BYTES {
            return Err(TrampolineError::InstructionTooShort {
                address: execute_address,
                instruction_len: displaced_len,
            });
        }
        let return_address = execute_address.checked_add(displaced_len as u64).ok_or(
            TrampolineError::ReturnAddressOverflow {
                address: execute_address,
                instruction_len: displaced_len,
            },
        )?;
        Ok(Self {
            execute_address,
            return_address,
            hook: Some(hook),
            actions: Vec::new(),
            controls: Vec::new(),
            clock: None,
            source_nops: original_nops::capture(scan, &instructions)?,
            instructions,
            logical_index: 0,
            relocated_start,
            ptrace_stops,
            kind: TrampolineKind::PatchWindow,
        })
    }

    /// Builds an exact, caller-certified displaced interval.
    ///
    /// The caller certifies that the interval stays in one function/basic block
    /// and that instructions before `logical` have straight-line flow. Entry,
    /// instruction-semantics, and publication obligations belong to the bundle
    /// planner. This constructor authenticates all three instruction boundaries
    /// and leaves the supplied snapshot untouched.
    pub(crate) fn from_window(
        scan: &ScanResult,
        physical: u64,
        logical: u64,
        end: u64,
        hook: HookCallback,
        replace: bool,
    ) -> Result<Self, TrampolineError> {
        Self::from_window_binding(scan, physical, logical, end, Some(hook), replace)
    }

    pub(crate) fn from_symbolic_window(
        scan: &ScanResult,
        physical: u64,
        logical: u64,
        end: u64,
        replace: bool,
    ) -> Result<Self, TrampolineError> {
        Self::from_window_binding(scan, physical, logical, end, None, replace)
    }

    fn from_window_binding(
        scan: &ScanResult,
        physical: u64,
        logical: u64,
        end: u64,
        hook: Option<HookCallback>,
        replace: bool,
    ) -> Result<Self, TrampolineError> {
        let start = scan
            .instructions()
            .iter()
            .position(|instruction| instruction.address() == physical)
            .ok_or(TrampolineError::SiteNotFound { address: physical })?;
        if physical > logical || logical >= end {
            return Err(TrampolineError::SiteNotFound { address: logical });
        }
        let mut cursor = physical;
        let mut instructions = Vec::new();
        let mut logical_index = None;
        for scanned in &scan.instructions()[start..] {
            if cursor == end {
                break;
            }
            if scanned.address() != cursor {
                return Err(encoding_error("displaced window is not contiguous"));
            }
            if cursor == logical {
                logical_index = Some(instructions.len());
            }
            cursor = cursor.checked_add(scanned.len() as u64).ok_or(
                TrampolineError::ReturnAddressOverflow {
                    address: cursor,
                    instruction_len: scanned.len(),
                },
            )?;
            if cursor > end {
                return Err(encoding_error(
                    "displaced window ends inside an instruction",
                ));
            }
            instructions.push(*scanned.instruction());
        }
        if cursor != end {
            return Err(encoding_error(
                "displaced window exceeds the instruction scan",
            ));
        }
        let logical_index =
            logical_index.ok_or(TrampolineError::SiteNotFound { address: logical })?;
        let displaced_len = usize::try_from(end - physical)
            .map_err(|_| TrampolineError::AddressNotRepresentable { address: end })?;
        if displaced_len < crate::patcher::NEAR_JUMP_BYTES {
            return Err(TrampolineError::InstructionTooShort {
                address: physical,
                instruction_len: displaced_len,
            });
        }
        Ok(Self {
            execute_address: physical,
            return_address: end,
            hook,
            actions: Vec::new(),
            controls: Vec::new(),
            clock: None,
            source_nops: original_nops::capture(scan, &instructions)?,
            instructions,
            logical_index,
            relocated_start: logical_index + usize::from(replace),
            ptrace_stops: false,
            kind: TrampolineKind::PatchWindow,
        })
    }

    /// Builds an observing or replacing plan for one short original instruction.
    ///
    /// The instruction must be one through four bytes long. No successor is
    /// copied: the hook belongs to this exact original PC and the continuation
    /// is the instruction's original end. The bundle planner owns instruction
    /// qualification, entry facts, and the separate short-pun publication proof.
    /// This does not relax the five-byte minimum of [`Self::from_window`].
    pub(crate) fn from_short_instruction(
        scan: &ScanResult,
        execute_address: u64,
        hook: HookCallback,
        replace: bool,
    ) -> Result<Self, TrampolineError> {
        Self::from_short_instruction_binding(scan, execute_address, Some(hook), replace)
    }

    pub(crate) fn from_symbolic_short_instruction(
        scan: &ScanResult,
        execute_address: u64,
        replace: bool,
    ) -> Result<Self, TrampolineError> {
        Self::from_short_instruction_binding(scan, execute_address, None, replace)
    }

    fn from_short_instruction_binding(
        scan: &ScanResult,
        execute_address: u64,
        hook: Option<HookCallback>,
        replace: bool,
    ) -> Result<Self, TrampolineError> {
        let scanned = scan
            .instructions()
            .iter()
            .find(|instruction| instruction.address() == execute_address)
            .ok_or(TrampolineError::SiteNotFound {
                address: execute_address,
            })?;
        if !(1..=4).contains(&scanned.len()) {
            return Err(encoding_error(
                "short instruction trampoline requires exactly one 1..=4-byte instruction",
            ));
        }
        let return_address = execute_address.checked_add(scanned.len() as u64).ok_or(
            TrampolineError::ReturnAddressOverflow {
                address: execute_address,
                instruction_len: scanned.len(),
            },
        )?;
        Ok(Self {
            execute_address,
            return_address,
            hook,
            actions: Vec::new(),
            controls: Vec::new(),
            clock: None,
            source_nops: original_nops::capture(scan, &[*scanned.instruction()])?,
            instructions: vec![*scanned.instruction()],
            logical_index: 0,
            relocated_start: usize::from(replace),
            ptrace_stops: false,
            kind: TrampolineKind::PatchWindow,
        })
    }

    /// Relocates exactly one whole instruction without calling a hook.
    ///
    /// The original successor is the continuation, even for instructions
    /// shorter than a redirect. Instruction qualification and the redirect's
    /// entry/publication proof remain the caller's responsibility.
    pub fn from_instruction(
        scan: &ScanResult,
        execute_address: u64,
    ) -> Result<Self, TrampolineError> {
        let scanned = scan
            .instructions()
            .iter()
            .find(|instruction| instruction.address() == execute_address)
            .ok_or(TrampolineError::SiteNotFound {
                address: execute_address,
            })?;
        if !(1..=15).contains(&scanned.len()) {
            return Err(encoding_error(
                "relocation requires one 1..=15-byte instruction",
            ));
        }
        let return_address = execute_address.checked_add(scanned.len() as u64).ok_or(
            TrampolineError::ReturnAddressOverflow {
                address: execute_address,
                instruction_len: scanned.len(),
            },
        )?;
        Ok(Self {
            execute_address,
            return_address,
            hook: None,
            actions: Vec::new(),
            controls: Vec::new(),
            clock: None,
            source_nops: original_nops::capture(scan, &[*scanned.instruction()])?,
            instructions: vec![*scanned.instruction()],
            logical_index: 0,
            relocated_start: 0,
            ptrace_stops: false,
            kind: TrampolineKind::Instruction,
        })
    }

    /// Builds one exact window with ordered, independent logical callbacks.
    ///
    /// Actions must name distinct instruction heads in strictly increasing
    /// address order. Each callback receives freshly saved state at that head;
    /// its Boolean selects replacement of that instruction only. Internal
    /// direct branches enter the destination's callback when one is present.
    /// The planner owns ISA, control-flow, entry and publication qualification.
    pub fn from_actions(
        scan: &ScanResult,
        physical: u64,
        end: u64,
        actions: &[(u64, HookCallback, bool)],
    ) -> Result<Self, TrampolineError> {
        let &(logical, hook, replace) = actions
            .first()
            .ok_or_else(|| encoding_error("coalesced window requires at least one action"))?;
        let mut plan = Self::from_window(scan, physical, logical, end, hook, replace)?;
        for (index, &(pc, _, _)) in actions.iter().enumerate() {
            if index > 0 && actions[index - 1].0 >= pc {
                return Err(encoding_error(
                    "logical actions must be strictly increasing",
                ));
            }
            if !plan
                .instructions
                .iter()
                .any(|instruction| instruction.ip() == pc)
            {
                return Err(TrampolineError::SiteNotFound { address: pc });
            }
        }
        plan.actions = actions.to_vec();
        plan.kind = TrampolineKind::Actions;
        Ok(plan)
    }

    /// Builds an observing window with independently controlled callbacks.
    ///
    /// Actions must name distinct original heads in strictly increasing order
    /// and use distinct control identities. Every original instruction executes
    /// whether its callback is enabled or disabled. Internal direct branches
    /// visit the target control on every logical visit. Conditional replacement
    /// is intentionally absent from this API.
    ///
    /// Each dispatch saves full application state before testing its control;
    /// disabling a callback is neither a cheap inactive path nor callback
    /// drainage. The caller still owns ISA, entry and publication qualification.
    pub fn from_controlled_actions(
        scan: &ScanResult,
        physical: u64,
        end: u64,
        actions: &[ControlledAction],
    ) -> Result<Self, TrampolineError> {
        for (index, action) in actions.iter().enumerate() {
            if actions[..index]
                .iter()
                .any(|previous| previous.control == action.control)
            {
                return Err(encoding_error(
                    "controlled actions require distinct control identities",
                ));
            }
        }
        let static_actions: Vec<_> = actions
            .iter()
            .map(|action| (action.logical_pc, action.control.callback(), false))
            .collect();
        let mut plan = Self::from_actions(scan, physical, end, &static_actions)?;
        plan.controls = actions.to_vec();
        Ok(plan)
    }

    /// Builds the finite single-head inline-clock profile before any emission.
    /// The higher-level planner also authenticates the complete authored source.
    pub fn from_backedge_clock(
        scan: &ScanResult,
        physical: u64,
        end: u64,
        action: &crate::backedge_clock::BackedgeClockAction,
    ) -> Result<Self, TrampolineError> {
        if physical != action.logical_pc
            || scan.instructions().first().map(|i| i.address()) != Some(action.base)
            || scan.snapshot() != action.source.as_slice()
        {
            return Err(encoding_error("inline clock source/site differs"));
        }
        let item = scan
            .instructions()
            .iter()
            .find(|i| i.address() == physical)
            .ok_or(TrampolineError::SiteNotFound { address: physical })?;
        let original = item.instruction();
        let expected = match action.condition {
            Some(5) => Code::Jne_rel32_64,
            Some(15) => Code::Jg_rel32_64,
            Some(2) => Code::Jb_rel32_64,
            None => Code::Jmp_rel32_64,
            _ => return Err(encoding_error("unsupported inline clock condition")),
        };
        if original.code() != expected
            || original.near_branch_target() >= physical
            || end != physical + item.len() as u64
        {
            return Err(encoding_error(
                "inline clock requires one exact near backedge",
            ));
        }
        let mut plan = Self::from_controlled_actions(
            scan,
            physical,
            end,
            &[ControlledAction {
                logical_pc: physical,
                control: action.control.clone(),
            }],
        )?;
        plan.clock = Some(Box::new(action.clone()));
        Ok(plan)
    }

    /// Exact immutable managed point associations retained by this plan.
    /// Read-only clones cannot recover managed write authority.
    pub fn controlled_actions(&self) -> &[ControlledAction] {
        &self.controls
    }

    /// Returns the first displaced instruction address.
    pub const fn execute_address(&self) -> u64 {
        self.execute_address
    }

    /// Returns the first logical hook PC, or the callback-free instruction PC.
    pub fn logical_address(&self) -> u64 {
        self.instructions[self.logical_index].ip()
    }

    /// Returns the first application address after the displaced window.
    pub const fn return_address(&self) -> u64 {
        self.return_address
    }

    /// Returns the number of complete application bytes displaced.
    pub fn displaced_len(&self) -> usize {
        self.instructions.iter().map(Instruction::len).sum()
    }

    /// Returns whether the first displaced instruction is replaced by the hook.
    pub const fn replaces_first(&self) -> bool {
        self.logical_index == 0 && self.relocated_start == 1
    }

    /// Emits this plan at an exact executable address.
    pub fn emit_at(&self, address: u64) -> Result<TrampolineImage, TrampolineError> {
        self.emit_at_recording(address, None)
    }

    /// Emits unchanged code with separately fallible producer frame metadata.
    ///
    /// This does not supply original CFI, register FDEs or admit unwinding.
    /// Unsupported metadata never removes an otherwise valid ordinary image.
    pub fn emit_with_frame_trace_at(&self, address: u64) -> Result<FrameEmission, TrampolineError> {
        self.emit_with_frame_trace_limits_at(address, FrameTraceLimits::default())
    }

    /// Emits code and metadata with independent, explicit metadata limits.
    pub fn emit_with_frame_trace_limits_at(
        &self,
        address: u64,
        limits: FrameTraceLimits,
    ) -> Result<FrameEmission, TrampolineError> {
        if self.clock.is_some() {
            return Err(encoding_error("inline clock frame metadata unsupported"));
        }
        let origin = if self.ptrace_stops {
            FrameEntryOrigin::ControllerOwnedStack
        } else {
            FrameEntryOrigin::ApplicationStack
        };
        let mut frames = FrameRecorder::new(origin, limits);
        if self.ptrace_stops {
            frames.refuse(FrameTraceRefusal::UnsupportedEntryOrigin);
        } else if matches!(self.kind, TrampolineKind::ExactSyscall) {
            frames.refuse(FrameTraceRefusal::ExactSyscallRequiresFrameContract);
        } else if self.relocated_start != self.logical_index
            || self.actions.iter().any(|action| action.2)
        {
            frames.refuse(FrameTraceRefusal::ReplacementRequiresFrameContract);
        }
        let image = self.emit_at_recording(address, Some(&mut frames))?;
        let trace = frames.finish(&image);
        Ok(FrameEmission::new(origin, image, trace))
    }

    fn emit_at_recording(
        &self,
        address: u64,
        frames: Option<&mut FrameRecorder>,
    ) -> Result<TrampolineImage, TrampolineError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (address, frames);
            return Err(TrampolineError::UnsupportedPlatform);
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            if matches!(
                self.kind,
                TrampolineKind::Instruction | TrampolineKind::Actions
            ) {
                return self.emit_actions_at(address, frames);
            }
            let extended_state = match self.kind {
                TrampolineKind::PatchWindow => SavedExtendedStateLayout::detect()?,
                TrampolineKind::ExactSyscall => SavedExtendedStateLayout::detect_with_mask(
                    PRESERVED_USER_STATE_MASK & !PKRU_XFEATURE,
                )?,
                TrampolineKind::Instruction | TrampolineKind::Actions => unreachable!(),
            };
            let prefix_instructions = &self.instructions[..self.logical_index];
            let prefix_block = if prefix_instructions.is_empty() {
                None
            } else {
                let prefix = self.encode_originals(0..self.logical_index, address, None)?;
                if prefix.terminal_jump_offset.is_some() || !prefix.branch_relays.is_empty() {
                    return Err(encoding_error(
                        "upstream prefix must have straight-line flow without branch relays",
                    ));
                }
                Some(prefix)
            };
            let prefix = prefix_block
                .as_ref()
                .map_or(&[][..], |block| block.encoded.code_buffer.as_slice());
            let hook_entry = address
                .checked_add(prefix.len() as u64)
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let entry_stop: &[u8] = if self.ptrace_stops {
                PTRACE_STOP_BYTES.as_slice()
            } else {
                &[]
            };
            let instrumentation_address = hook_entry
                .checked_add(entry_stop.len() as u64)
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let recording = frames.as_deref().is_some_and(FrameRecorder::recording);
            let mut instrumentation_frames = HelperFrames::new(FrameStage::SaveAndCall);
            let mut restore_frames = HelperFrames::new(FrameStage::Restore);
            let instrumentation = self
                .encode_instrumentation(
                    instrumentation_address,
                    &extended_state,
                    self.logical_address(),
                    (
                        Some(self.hook.expect("legacy plan always has a callback")),
                        None,
                    ),
                    None,
                    recording.then_some(&mut instrumentation_frames),
                )?
                .bytes;
            let restore_address = instrumentation_address
                .checked_add(instrumentation.len() as u64)
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let restore = encode_restore(
                restore_address,
                &extended_state,
                recording.then_some(&mut restore_frames),
            )?;
            let completion_stop_address = restore_address
                .checked_add(restore.len() as u64)
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let completion_stop: &[u8] = if self.ptrace_stops {
                PTRACE_STOP_BYTES.as_slice()
            } else {
                &[]
            };
            let relocated_address = completion_stop_address
                .checked_add(completion_stop.len() as u64)
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let relocated_instructions = &self.instructions[self.relocated_start..];
            let observing_entry =
                (self.relocated_start == self.logical_index).then_some(self.logical_address());
            let relocated_block = match self.kind {
                TrampolineKind::ExactSyscall => None,
                TrampolineKind::PatchWindow => Some(self.encode_originals(
                    self.relocated_start..self.instructions.len(),
                    relocated_address,
                    observing_entry,
                )?),
                TrampolineKind::Instruction | TrampolineKind::Actions => unreachable!(),
            };
            let relocated = relocated_block
                .as_ref()
                .map_or(&[][..], |block| block.encoded.code_buffer.as_slice());
            let return_jump_address = relocated_address
                .checked_add(relocated.len() as u64)
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let return_jump = encode_return_jump(return_jump_address, self.return_address)?;
            let layout = TrampolineLayout {
                relocated_prefix_len: prefix.len(),
                entry_stop_len: entry_stop.len(),
                instrumentation_len: instrumentation.len(),
                restore_len: restore.len(),
                completion_stop_len: completion_stop.len(),
                relocated_len: relocated.len(),
                return_len: return_jump.len(),
                saved_extended_state: extended_state,
            };
            let total_len = layout.total_len().ok_or(TrampolineError::CodeTooLarge {
                code_len: usize::MAX,
                allocation_len: TRAMPOLINE_ALLOCATION_BYTES,
            })?;
            let mut bytes = Vec::with_capacity(total_len);
            bytes.extend_from_slice(prefix);
            bytes.extend_from_slice(entry_stop);
            bytes.extend_from_slice(&instrumentation);
            bytes.extend_from_slice(&restore);
            bytes.extend_from_slice(completion_stop);
            bytes.extend_from_slice(relocated);
            bytes.extend_from_slice(&return_jump);
            debug_assert_eq!(bytes.len(), total_len);

            let mut program_counters = Vec::new();
            let mut instruction_boundaries = Vec::new();
            if let Some(block) = prefix_block.as_ref() {
                append_relocated_program_counter_mappings(
                    &mut program_counters,
                    &mut instruction_boundaries,
                    address,
                    prefix,
                    prefix_instructions,
                    &block.encoded.new_instruction_offsets,
                    None,
                )?;
            }
            push_program_counter_mapping(
                &mut program_counters,
                hook_entry,
                relocated_address,
                self.logical_address(),
            );
            if let Some(block) = relocated_block.as_ref() {
                append_relocated_program_counter_mappings(
                    &mut program_counters,
                    &mut instruction_boundaries,
                    relocated_address,
                    &relocated[..block.terminal_jump_offset.unwrap_or(relocated.len())],
                    relocated_instructions,
                    &block.encoded.new_instruction_offsets,
                    observing_entry,
                )?;
                if let Some(offset) = block.terminal_jump_offset {
                    // The terminal transfer represents the continuation. Padding
                    // and pointers after it are data, not displaced instructions.
                    push_program_counter_mapping(
                        &mut program_counters,
                        relocated_address + offset as u64,
                        relocated_address + offset as u64 + NEAR_RETURN_JUMP_BYTES as u64,
                        self.return_address,
                    );
                }
                for relay in &block.branch_relays {
                    // ENDBR64 and the NOTRACK jump represent the original direct
                    // branch destination. The following absolute target is data.
                    push_program_counter_mapping(
                        &mut program_counters,
                        relocated_address + relay.offset as u64,
                        relocated_address + relay.offset as u64 + BRANCH_RELAY_CODE.len() as u64,
                        relay.target,
                    );
                }
            }
            let return_code_len = if return_jump.len() == NOTRACK_ABSOLUTE_JUMP_BYTES {
                return_jump.len() - core::mem::size_of::<u64>()
            } else {
                return_jump.len()
            };
            let return_jump_end = return_jump_address
                .checked_add(return_jump.len() as u64)
                .ok_or(TrampolineError::AddressNotRepresentable {
                    address: return_jump_address,
                })?;
            push_program_counter_mapping(
                &mut program_counters,
                return_jump_address,
                return_jump_end - (return_jump.len() - return_code_len) as u64,
                self.return_address,
            );
            let mut entry_routes = instruction_boundaries.clone();
            if let Some((_, generated)) = entry_routes
                .iter_mut()
                .find(|(original, _)| *original == self.logical_address())
            {
                *generated = hook_entry;
            } else {
                entry_routes.push((self.logical_address(), hook_entry));
                entry_routes.sort_unstable_by_key(|(original, _)| *original);
            }
            if let Some(frames) = frames {
                if let Some(block) = prefix_block.as_ref() {
                    record_relocated_frames(frames, prefix_instructions, address, block);
                }
                frames.helper(
                    self.logical_address(),
                    instrumentation_address,
                    &instrumentation,
                    instrumentation_frames,
                );
                frames.helper(
                    self.logical_address(),
                    restore_address,
                    &restore,
                    restore_frames,
                );
                if let Some(block) = relocated_block.as_ref() {
                    record_relocated_frames(
                        frames,
                        relocated_instructions,
                        relocated_address,
                        block,
                    );
                }
                frames.return_jump(return_jump_address, return_jump.len(), self.return_address);
            }
            Ok(TrampolineImage {
                clock: None,
                clock_gate: None,
                artifact: None,
                address,
                bytes,
                layout,
                program_counters,
                entry_routes,
                instruction_boundaries,
                controls: self
                    .controls
                    .iter()
                    .map(|action| action.control.clone())
                    .collect(),
            })
        }
    }

    // Preserve scanner-owned NOP bytes without changing branch relocation,
    // literal-pool handling or the original instructions used by PC/frame maps.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn encode_originals(
        &self,
        range: core::ops::Range<usize>,
        address: u64,
        observing_entry: Option<u64>,
    ) -> Result<RelocatedBlock, TrampolineError> {
        let instructions = self.instructions[range.clone()]
            .iter()
            .zip(&self.source_nops[range.clone()])
            .map(|(original, bytes)| original_nops::instruction(original, bytes.as_deref()))
            .collect::<Result<Vec<_>, _>>()?;
        let block = encode_relocated_block(&instructions, address, observing_entry)?;
        for (index, bytes) in self.source_nops[range].iter().enumerate() {
            if let Some(bytes) = bytes {
                original_nops::verify(&block.encoded, index, bytes)?;
            }
        }
        Ok(block)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn emit_actions_at(
        &self,
        address: u64,
        frames: Option<&mut FrameRecorder>,
    ) -> Result<TrampolineImage, TrampolineError> {
        self.emit_ordered_at(address, None, frames)
    }

    pub(crate) fn emit_artifact_at(
        &self,
        address: u64,
        input: &ArtifactEmission,
    ) -> Result<TrampolineImage, TrampolineError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (address, input);
            return Err(TrampolineError::UnsupportedPlatform);
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            if self.ptrace_stops
                || self.clock.is_some()
                || !self.controls.is_empty()
                || !matches!(
                    self.kind,
                    TrampolineKind::PatchWindow | TrampolineKind::Instruction
                )
            {
                return Err(artifact_error(
                    "artifact profile does not implement ptrace, controlled or multi-action binding",
                ));
            }
            self.emit_ordered_at(address, Some(input), None)
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn emit_ordered_at(
        &self,
        address: u64,
        artifact: Option<&ArtifactEmission>,
        frames: Option<&mut FrameRecorder>,
    ) -> Result<TrampolineImage, TrampolineError> {
        if self.clock.is_some() && (artifact.is_some() || frames.is_some() || self.ptrace_stops) {
            return Err(encoding_error(
                "inline clock supports only live ordinary emission",
            ));
        }
        let extended_state = match artifact {
            Some(input) => input.profile().saved_state(),
            None => SavedExtendedStateLayout::detect()?,
        };
        let actions: Vec<(u64, Option<HookCallback>, bool)> = match artifact {
            Some(_) if self.kind == TrampolineKind::PatchWindow => vec![(
                self.logical_address(),
                None,
                self.relocated_start != self.logical_index,
            )],
            Some(_) => Vec::new(),
            None => self
                .actions
                .iter()
                .map(|&(pc, hook, replace)| (pc, Some(hook), replace))
                .collect(),
        };
        let mut fragments = Vec::new();
        let mut original_operands = Vec::new();
        let mut emitted_nops = Vec::new();
        // Give every encoder label an identity distinct from *all* original
        // addresses and operands. Direct branches are retargeted explicitly;
        // RIP-relative data references must never follow an encoder label.
        let mut next_identity = 0_u32;
        let mut identity = || -> Result<u64, TrampolineError> {
            loop {
                let candidate = u64::from(
                    u16::try_from(next_identity)
                        .map_err(|_| encoding_error("coalesced encoder identities exhausted"))?,
                );
                next_identity += 1;
                if !self.instructions.iter().any(|instruction| {
                    instruction.ip() == candidate
                        || (instruction.is_ip_rel_memory_operand()
                            && instruction.ip_rel_memory_address() == candidate)
                        || (matches!(
                            instruction.op0_kind(),
                            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                        ) && instruction.near_branch_target() == candidate)
                }) {
                    return Ok(candidate);
                }
            }
        };
        let entry_identities = (0..self.instructions.len())
            .map(|_| identity())
            .collect::<Result<Vec<_>, _>>()?;
        let mut encoded_instructions = Vec::new();
        let mut heads = Vec::new();
        let mut first_hook_lengths = None;
        let mut helper_frames = Vec::new();
        let mut action_index = 0;
        let mut clock_spec = None;
        let mut clock_observer = None;
        for (index, original) in self.instructions.iter().enumerate() {
            let entry_index = encoded_instructions.len();
            let mut entry = Instruction::with(Code::Zero_bytes);
            entry.set_ip(entry_identities[index]);
            encoded_instructions.push(entry);
            let action = actions
                .get(action_index)
                .filter(|action| action.0 == original.ip());
            let clock_labels = if self.clock.is_some() {
                Some((identity()?, identity()?))
            } else {
                None
            };
            let mut observing_index = entry_index;
            if let Some(clock) = &self.clock {
                let (observer, body) = clock_labels.unwrap();
                clock_spec = Some(backedge_clock::append(
                    &mut encoded_instructions,
                    clock,
                    observer,
                    body,
                    &mut identity,
                )?);
                observing_index = encoded_instructions.len();
                let mut marker = Instruction::with(Code::Zero_bytes);
                marker.set_ip(observer);
                encoded_instructions.push(marker);
                clock_observer = Some(observing_index);
            }
            if let Some(&(_, hook, _)) = action {
                // These helpers use only register/stack operands, absolute MOV
                // immediates and internal relative branches. Their byte strings
                // are position independent and remain contiguous below.
                let recording = frames.as_deref().is_some_and(FrameRecorder::recording);
                let mut instrumentation_frames = HelperFrames::new(FrameStage::SaveAndCall);
                let mut restore_frames = HelperFrames::new(FrameStage::Restore);
                let instrumentation = self.encode_instrumentation(
                    0,
                    &extended_state,
                    original.ip(),
                    (
                        hook,
                        self.controls
                            .get(action_index)
                            .map(|action| &action.control),
                    ),
                    artifact,
                    recording.then_some(&mut instrumentation_frames),
                )?;
                let restore = encode_restore(
                    instrumentation.bytes.len() as u64,
                    &extended_state,
                    recording.then_some(&mut restore_frames),
                )?;
                first_hook_lengths.get_or_insert((
                    observing_index,
                    instrumentation.bytes.len(),
                    restore.len(),
                ));
                for bytes in [instrumentation.bytes.as_slice(), restore.as_slice()] {
                    for chunk in bytes.chunks(16) {
                        let mut directive =
                            Instruction::with_declare_byte(chunk).map_err(encoding_error)?;
                        directive.set_ip(identity()?);
                        encoded_instructions.push(directive);
                    }
                }
                if recording {
                    helper_frames.push((
                        entry_index,
                        original.ip(),
                        instrumentation.bytes.len(),
                        restore.len(),
                        instrumentation_frames,
                        restore_frames,
                    ));
                }
                fragments.push((entry_index, instrumentation));
                action_index += 1;
            }
            let body_index = encoded_instructions.len();
            let mut body = Instruction::with(Code::Zero_bytes);
            body.set_ip(match clock_labels {
                Some((_, body)) => body,
                None => identity()?,
            });
            encoded_instructions.push(body);
            let replaced = action.is_some_and(|action| action.2);
            if !replaced {
                let retained_nop = self.source_nops[index].as_deref();
                let mut instruction = original_nops::instruction(original, retained_nop)?;
                instruction.set_ip(identity()?);
                let internal_target = if matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ) {
                    self.instructions
                        .iter()
                        .position(|head| head.ip() == original.near_branch_target())
                } else {
                    None
                };
                if let Some(target) = internal_target {
                    let target = entry_identities[target];
                    match instruction.op0_kind() {
                        OpKind::NearBranch16 => instruction.set_near_branch16(target as u16),
                        OpKind::NearBranch32 => instruction.set_near_branch32(target as u32),
                        OpKind::NearBranch64 => instruction.set_near_branch64(target),
                        _ => unreachable!(),
                    }
                }
                if let Some(bytes) = retained_nop {
                    emitted_nops.push((encoded_instructions.len(), bytes));
                }
                original_operands.push((encoded_instructions.len(), *original));
                encoded_instructions.push(instruction);
            }
            heads.push((original.ip(), entry_index, body_index, replaced));
        }
        let block = if self.clock.is_some() {
            // All gate branches keep their exact forms; no indirect expansion,
            // absolute literal or rel8 JRCXZ rewrite is admitted for this profile.
            let encoded = BlockEncoder::encode(
                64,
                InstructionBlock::new(&encoded_instructions, address),
                BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS
                    | BlockEncoderOptions::RETURN_RELOC_INFOS
                    | BlockEncoderOptions::DONT_FIX_BRANCHES,
            )
            .map_err(encoding_error)?;
            if !encoded.reloc_infos.is_empty() {
                return Err(encoding_error("inline gate created absolute fixup"));
            }
            RelocatedBlock {
                encoded,
                terminal_jump_offset: None,
                branch_relays: Vec::new(),
            }
        } else {
            encode_relocated_block_with_metadata(
                &encoded_instructions,
                address,
                None,
                artifact.is_some(),
            )?
        };
        for &(index, bytes) in &emitted_nops {
            original_nops::verify(&block.encoded, index, bytes)?;
        }
        let offset = |index: usize| -> Result<usize, TrampolineError> {
            block
                .encoded
                .new_instruction_offsets
                .get(index)
                .copied()
                .filter(|offset| *offset != u32::MAX)
                .map(|offset| offset as usize)
                .ok_or_else(|| encoding_error("coalesced encoder lost an instruction label"))
        };
        let generated = |offset: usize| {
            address
                .checked_add(offset as u64)
                .ok_or(TrampolineError::AddressNotRepresentable { address })
        };
        if let Some(spec) = &clock_spec {
            backedge_clock::verify(spec, &encoded_instructions, address, &block.encoded)?;
        }
        let clock_gate = match clock_observer {
            Some(observer) => Some(crate::backedge_clock::ClockGateLayout {
                entry: generated(offset(heads[0].1)?)?,
                observing_entry: generated(offset(observer)?)?,
                original_body: generated(offset(heads[0].2)?)?,
            }),
            None => None,
        };
        let mut entry_routes = Vec::new();
        let mut instruction_boundaries = Vec::new();
        let mut program_counters = Vec::new();
        let executable_end = block
            .terminal_jump_offset
            .unwrap_or(block.encoded.code_buffer.len());
        for (index, &(pc, entry, body, replaced)) in heads.iter().enumerate() {
            let start = generated(offset(entry)?)?;
            let end = generated(if let Some(next) = heads.get(index + 1) {
                offset(next.1)?
            } else {
                executable_end
            })?;
            entry_routes.push((pc, start));
            if !replaced {
                instruction_boundaries.push((pc, generated(offset(body)?)?));
            }
            push_program_counter_mapping(&mut program_counters, start, end, pc);
        }
        if let Some(offset) = block.terminal_jump_offset {
            push_program_counter_mapping(
                &mut program_counters,
                generated(offset)?,
                generated(offset + NEAR_RETURN_JUMP_BYTES)?,
                self.return_address,
            );
        }
        for relay in &block.branch_relays {
            push_program_counter_mapping(
                &mut program_counters,
                generated(relay.offset)?,
                generated(relay.offset + BRANCH_RELAY_CODE.len())?,
                relay.target,
            );
        }
        let return_start = generated(block.encoded.code_buffer.len())?;
        let return_fragment = artifact.map(|input| {
            artifact_fragments::return_jump(artifact_target(input, self.return_address))
        });
        let return_jump = match &return_fragment {
            Some(fragment) => fragment.bytes.clone(),
            None => encode_return_jump(return_start, self.return_address)?,
        };
        if self.clock.is_some() && return_jump.len() != NEAR_RETURN_JUMP_BYTES {
            return Err(encoding_error(
                "inline clock requires exact near fallthrough continuation",
            ));
        }
        let return_code_len = if return_jump.len() == NOTRACK_ABSOLUTE_JUMP_BYTES {
            return_jump.len() - core::mem::size_of::<u64>()
        } else {
            return_jump.len()
        };
        let total_len = block
            .encoded
            .code_buffer
            .len()
            .checked_add(return_jump.len())
            .ok_or_else(|| encoding_error("coalesced image length overflow"))?;
        generated(total_len)?;
        push_program_counter_mapping(
            &mut program_counters,
            return_start,
            generated(block.encoded.code_buffer.len() + return_code_len)?,
            self.return_address,
        );
        let (prefix_len, instrumentation_len, restore_len) = match first_hook_lengths {
            Some((entry, instrumentation, restore)) => (offset(entry)?, instrumentation, restore),
            None => (0, 0, 0),
        };
        let relocated_len = block
            .encoded
            .code_buffer
            .len()
            .checked_sub(prefix_len + instrumentation_len + restore_len)
            .ok_or_else(|| encoding_error("coalesced hook exceeds emitted image"))?;
        let layout = TrampolineLayout {
            relocated_prefix_len: prefix_len,
            instrumentation_len,
            restore_len,
            relocated_len,
            return_len: return_jump.len(),
            saved_extended_state: extended_state,
            ..TrampolineLayout::default()
        };
        if let Some(frames) = frames {
            if block.terminal_jump_offset.is_some()
                || !block.branch_relays.is_empty()
                || block.encoded.new_instruction_offsets.contains(&u32::MAX)
            {
                frames.refuse(FrameTraceRefusal::ExpandedRelocation);
            }
            for (
                entry,
                pc,
                instrumentation_len,
                restore_len,
                instrumentation_frames,
                restore_frames,
            ) in helper_frames
            {
                let helper_offset = match offset(entry) {
                    Ok(offset) => offset,
                    Err(_) => {
                        frames.refuse(FrameTraceRefusal::InvalidProducerAnnotation);
                        continue;
                    }
                };
                let restore_offset = helper_offset.checked_add(instrumentation_len);
                let helper_end = restore_offset.and_then(|value| value.checked_add(restore_len));
                if let (Some(restore_offset), Some(helper_end)) = (restore_offset, helper_end) {
                    if let (Some(instrumentation), Some(restore), Ok(start), Ok(restored)) = (
                        block.encoded.code_buffer.get(helper_offset..restore_offset),
                        block.encoded.code_buffer.get(restore_offset..helper_end),
                        generated(helper_offset),
                        generated(restore_offset),
                    ) {
                        frames.helper(pc, start, instrumentation, instrumentation_frames);
                        frames.helper(pc, restored, restore, restore_frames);
                    } else {
                        frames.refuse(FrameTraceRefusal::IncompleteByteOwnership);
                    }
                } else {
                    frames.refuse(FrameTraceRefusal::ArithmeticOverflow);
                }
            }
            for (index, &(_, _, body, replaced)) in heads.iter().enumerate() {
                if !replaced {
                    let start = offset(body).and_then(generated);
                    let end = heads
                        .get(index + 1)
                        .map_or(Ok(executable_end), |next| offset(next.1))
                        .and_then(generated);
                    match (start, end) {
                        (Ok(start), Ok(end)) => {
                            frames.relocated(self.instructions[index], start, end)
                        }
                        _ => frames.refuse(FrameTraceRefusal::InvalidProducerAnnotation),
                    }
                }
            }
            frames.return_jump(return_start, return_jump.len(), self.return_address);
        }
        let mut fields = Vec::new();
        if let Some(input) = artifact {
            for (entry, fragment) in &fragments {
                let start = offset(*entry)?;
                if block
                    .encoded
                    .code_buffer
                    .get(start..start + fragment.bytes.len())
                    != Some(fragment.bytes.as_slice())
                {
                    return Err(artifact_error(
                        "fixed instrumentation fragment moved or changed",
                    ));
                }
                for field in &fragment.fields {
                    fields.push(field.rebased(start as u64).map_err(artifact_fixup_error)?);
                }
            }
            append_artifact_original_fields(
                &mut fields,
                input,
                address,
                &block.encoded,
                &original_operands,
                &entry_routes,
            )?;
            if let Some(fragment) = &return_fragment {
                for field in &fragment.fields {
                    fields.push(
                        field
                            .rebased(block.encoded.code_buffer.len() as u64)
                            .map_err(artifact_fixup_error)?,
                    );
                }
            }
        }
        let mut bytes = block.encoded.code_buffer;
        bytes.extend_from_slice(&return_jump);
        let artifact = if let Some(input) = artifact {
            let placement = ImagePlacement {
                image: ImageId(address),
                address: RelativeAddress {
                    domain: BiasDomain(input.profile().bias_domain()),
                    offset: i128::from(address),
                },
                len: bytes.len() as u64,
            };
            bytes = fixups::link_bias_invariant(ImageId(address), &bytes, &fields, &[placement])
                .map_err(artifact_fixup_error)?;
            Some(artifact_metadata(
                input,
                address,
                &fields,
                self.kind != TrampolineKind::Instruction,
            )?)
        } else {
            None
        };
        debug_assert_eq!(layout.total_len(), Some(bytes.len()));
        Ok(TrampolineImage {
            clock: self.clock.as_ref().map(|action| action.clock.clone()),
            clock_gate,
            artifact,
            address,
            bytes,
            layout,
            program_counters,
            entry_routes,
            instruction_boundaries,
            controls: self
                .controls
                .iter()
                .map(|action| action.control.clone())
                .collect(),
        })
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn encode_instrumentation(
        &self,
        address: u64,
        extended_state: &SavedExtendedStateLayout,
        logical_address: u64,
        hook_control: (Option<HookCallback>, Option<&ProbeControl>),
        artifact: Option<&ArtifactEmission>,
        mut frames: Option<&mut HelperFrames>,
    ) -> Result<InstrumentationEmission, TrampolineError> {
        let (hook, control) = hook_control;
        let mut fragments = Vec::new();
        let mut assembler = CodeAssembler::new(64).map_err(encoding_error)?;
        assembler
            .lea(rsp, rsp - SYSTEM_V_RED_ZONE_BYTES)
            .map_err(encoding_error)?;
        record_frame_effect(
            &mut frames,
            &assembler,
            FrameEffect::Reserve(SYSTEM_V_RED_ZONE_BYTES),
        );
        // Reserve the descriptor immediately below the untouched application
        // red zone. Flags and GPR pushes below it retain every pre-existing
        // HookContext offset, while the descriptor becomes its 32-byte tail.
        assembler
            .lea(rsp, rsp - SAVED_EXTENDED_STATE_DESCRIPTOR_BYTES)
            .map_err(encoding_error)?;
        record_frame_effect(
            &mut frames,
            &assembler,
            FrameEffect::Reserve(SAVED_EXTENDED_STATE_DESCRIPTOR_BYTES),
        );
        assembler.pushfq().map_err(encoding_error)?;
        record_frame_effect(&mut frames, &assembler, FrameEffect::SaveFlags);
        for register in [
            rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
        ] {
            assembler.push(register).map_err(encoding_error)?;
            if let Some(frames) = frames.as_deref_mut() {
                let source = assembler
                    .instructions()
                    .last()
                    .expect("successful PUSH is present");
                frames.after(
                    assembler.instructions().len(),
                    FrameEffect::SaveRegister(source.op0_register()),
                );
            }
        }
        if self.ptrace_stops {
            // The authenticated entry controller placed the application RSP in
            // the last word of the owned stack. Saving flags and fifteen GPRs
            // after the descriptor and red zone leaves RSP exactly 288 bytes
            // below owned_top. This slot is 280 bytes above the current frame
            // and has not been overwritten. No instruction before this load
            // dereferences the application stack.
            assembler
                .mov(
                    rax,
                    qword_ptr(
                        rsp + SAVED_EXTENDED_STATE_DESCRIPTOR_BYTES
                            + SYSTEM_V_RED_ZONE_BYTES
                            + SAVED_INTEGER_BYTES
                            - core::mem::size_of::<u64>() as i32,
                    ),
                )
                .map_err(encoding_error)?;
        } else {
            assembler
                .lea(
                    rax,
                    rsp + SAVED_EXTENDED_STATE_DESCRIPTOR_BYTES
                        + SYSTEM_V_RED_ZONE_BYTES
                        + SAVED_INTEGER_BYTES,
                )
                .map_err(encoding_error)?;
        }
        assembler.push(rax).map_err(encoding_error)?;
        record_frame_effect(&mut frames, &assembler, FrameEffect::MetadataWord);
        if let Some(input) = artifact {
            let fragment = artifact_fragments::logical_pc(artifact_target(input, logical_address));
            fragments.push((assembler.instructions().len(), fragment.clone()));
            assembler.db(&fragment.bytes).map_err(encoding_error)?;
        } else {
            assembler
                .mov(rax, logical_address)
                .map_err(encoding_error)?;
            assembler.push(rax).map_err(encoding_error)?;
            record_frame_effect(&mut frames, &assembler, FrameEffect::MetadataWord);
        }
        assembler.mov(r12, rsp).map_err(encoding_error)?;
        record_frame_effect(&mut frames, &assembler, FrameEffect::AnchorContext);
        extended_state.encode_save(&mut assembler)?;
        let descriptor_offset = core::mem::offset_of!(HookContext, saved_extended_state) as i32;
        assembler
            .mov(
                qword_ptr(
                    r12 + descriptor_offset
                        + core::mem::offset_of!(SavedExtendedStateDescriptor, address) as i32,
                ),
                rsp,
            )
            .map_err(encoding_error)?;
        for (offset, value) in [
            (
                core::mem::offset_of!(SavedExtendedStateDescriptor, len),
                extended_state.len(),
            ),
            (
                core::mem::offset_of!(SavedExtendedStateDescriptor, mask),
                extended_state.mask(),
            ),
            (
                core::mem::offset_of!(SavedExtendedStateDescriptor, format),
                extended_state.format().raw(),
            ),
        ] {
            assembler.mov(rax, value).map_err(encoding_error)?;
            assembler
                .mov(qword_ptr(r12 + descriptor_offset + offset as i32), rax)
                .map_err(encoding_error)?;
        }
        assembler.cld().map_err(encoding_error)?;
        assembler.mov(rdi, r12).map_err(encoding_error)?;
        if let Some(input) = artifact {
            if control.is_some() || hook.is_some() {
                return Err(artifact_error(
                    "process callback/control cannot enter artifact emission",
                ));
            }
            let target = input
                .hook()
                .address
                .map(|address| artifact_target(input, address))
                .unwrap_or(Target::UnresolvedSymbol(input.hook().identity));
            let fragment = artifact_fragments::hook_call(target);
            fragments.push((assembler.instructions().len(), fragment.clone()));
            assembler.db(&fragment.bytes).map_err(encoding_error)?;
        } else {
            if let Some(control) = control {
                // Application RSI was saved before this instrumentation-private
                // argument. The stable block is retained for the code lifetime.
                assembler
                    .mov(rsi, control.block_address())
                    .map_err(encoding_error)?;
                assembler
                    .mov(rax, crate::controls::dispatch as *const () as usize as u64)
                    .map_err(encoding_error)?;
            } else {
                // Keep the legacy static callback path byte-for-byte unchanged.
                assembler
                    .mov(
                        rax,
                        hook.expect("live instrumentation has a real callback") as usize as u64,
                    )
                    .map_err(encoding_error)?;
            }
            assembler.call(rax).map_err(encoding_error)?;
            if let Some(frames) = frames.as_deref_mut() {
                frames.call(
                    assembler.instructions().len(),
                    if control.is_some() {
                        FrameCallKind::ControlDispatcher
                    } else {
                        FrameCallKind::Observer
                    },
                );
            }
        }
        if artifact.is_none() {
            return Ok(InstrumentationEmission {
                bytes: assemble_frame_helper(&mut assembler, address, frames)?,
                fields: Vec::new(),
            });
        }
        let encoded = assembler
            .assemble_options(address, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .map_err(encoding_error)?
            .inner;
        let mut fields = Vec::new();
        for (index, fragment) in fragments {
            let offset = encoded
                .new_instruction_offsets
                .get(index)
                .copied()
                .filter(|value| *value != u32::MAX)
                .ok_or_else(|| artifact_error("instrumentation fragment has no encoder offset"))?
                as usize;
            if encoded
                .code_buffer
                .get(offset..offset + fragment.bytes.len())
                != Some(fragment.bytes.as_slice())
            {
                return Err(artifact_error("instrumentation fragment is not contiguous"));
            }
            for field in fragment.fields {
                fields.push(field.rebased(offset as u64).map_err(artifact_fixup_error)?);
            }
        }
        Ok(InstrumentationEmission {
            bytes: encoded.code_buffer,
            fields,
        })
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn encode_restore(
    address: u64,
    extended_state: &SavedExtendedStateLayout,
    mut frames: Option<&mut HelperFrames>,
) -> Result<Vec<u8>, TrampolineError> {
    let mut assembler = CodeAssembler::new(64).map_err(encoding_error)?;
    extended_state.encode_restore(&mut assembler)?;
    assembler.mov(rsp, r12).map_err(encoding_error)?;
    record_frame_effect(&mut frames, &assembler, FrameEffect::RestoreStack);
    assembler
        .add(rsp, HOOK_METADATA_BYTES)
        .map_err(encoding_error)?;
    record_frame_effect(&mut frames, &assembler, FrameEffect::SkipMetadata);
    for register in [
        r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax,
    ] {
        assembler.pop(register).map_err(encoding_error)?;
        if let Some(frames) = frames.as_deref_mut() {
            let source = assembler
                .instructions()
                .last()
                .expect("successful POP is present");
            frames.after(
                assembler.instructions().len(),
                FrameEffect::RestoreRegister(source.op0_register()),
            );
        }
    }
    assembler.popfq().map_err(encoding_error)?;
    record_frame_effect(&mut frames, &assembler, FrameEffect::RestoreFlags);
    assembler
        .lea(rsp, rsp + SAVED_EXTENDED_STATE_DESCRIPTOR_BYTES)
        .map_err(encoding_error)?;
    record_frame_effect(
        &mut frames,
        &assembler,
        FrameEffect::Release(SAVED_EXTENDED_STATE_DESCRIPTOR_BYTES),
    );
    assembler
        .lea(rsp, rsp + SYSTEM_V_RED_ZONE_BYTES)
        .map_err(encoding_error)?;
    record_frame_effect(
        &mut frames,
        &assembler,
        FrameEffect::Release(SYSTEM_V_RED_ZONE_BYTES),
    );
    assemble_frame_helper(&mut assembler, address, frames)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn record_frame_effect(
    frames: &mut Option<&mut HelperFrames>,
    assembler: &CodeAssembler,
    effect: FrameEffect,
) {
    if let Some(frames) = frames.as_deref_mut() {
        frames.after(assembler.instructions().len(), effect);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn assemble_frame_helper(
    assembler: &mut CodeAssembler,
    address: u64,
    frames: Option<&mut HelperFrames>,
) -> Result<Vec<u8>, TrampolineError> {
    if let Some(frames) = frames {
        let result = assembler
            .assemble_options(address, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .map_err(encoding_error)?;
        frames.finish(assembler.instructions(), &result.inner);
        Ok(result.inner.code_buffer)
    } else {
        assembler.assemble(address).map_err(encoding_error)
    }
}

fn record_relocated_frames(
    frames: &mut FrameRecorder,
    instructions: &[Instruction],
    address: u64,
    block: &RelocatedBlock,
) {
    if !frames.recording() {
        return;
    }
    let offsets = &block.encoded.new_instruction_offsets;
    if block.terminal_jump_offset.is_some()
        || !block.branch_relays.is_empty()
        || offsets.contains(&u32::MAX)
    {
        frames.refuse(FrameTraceRefusal::ExpandedRelocation);
        return;
    }
    if offsets.len() != instructions.len() {
        frames.refuse(FrameTraceRefusal::InvalidProducerAnnotation);
        return;
    }
    for (index, instruction) in instructions.iter().enumerate() {
        let start = address.checked_add(offsets[index] as u64);
        let end = address.checked_add(
            offsets
                .get(index + 1)
                .map_or(block.encoded.code_buffer.len() as u64, |offset| {
                    u64::from(*offset)
                }),
        );
        match (start, end) {
            (Some(start), Some(end)) => frames.relocated(*instruction, start, end),
            _ => frames.refuse(FrameTraceRefusal::ArithmeticOverflow),
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn encoding_error(error: impl fmt::Display) -> TrampolineError {
    TrampolineError::Encoding {
        message: error.to_string(),
    }
}

fn encode_return_jump(address: u64, target: u64) -> Result<Vec<u8>, TrampolineError> {
    let next_ip = address
        .checked_add(NEAR_RETURN_JUMP_BYTES as u64)
        .ok_or(TrampolineError::AddressNotRepresentable { address })?;
    if let Ok(displacement) = i32::try_from(i128::from(target) - i128::from(next_ip)) {
        let mut bytes = Vec::with_capacity(NEAR_RETURN_JUMP_BYTES);
        bytes.push(0xE9);
        bytes.extend_from_slice(&displacement.to_le_bytes());
        return Ok(bytes);
    }

    // The DS prefix is CET's NOTRACK override. It makes the rare indirect
    // fallback independent of an ENDBR64 at the application continuation.
    let mut bytes = Vec::with_capacity(NOTRACK_ABSOLUTE_JUMP_BYTES);
    bytes.extend_from_slice(&[0x3E, 0xFF, 0x25, 0, 0, 0, 0]);
    bytes.extend_from_slice(&target.to_le_bytes());
    Ok(bytes)
}

fn push_program_counter_mapping(
    mappings: &mut Vec<ProgramCounterMapping>,
    generated_start: u64,
    generated_end: u64,
    logical_address: u64,
) {
    if generated_start >= generated_end {
        return;
    }
    match mappings.last_mut() {
        Some(previous)
            if previous.generated_end == generated_start
                && previous.logical_address == logical_address =>
        {
            previous.generated_end = generated_end;
            return;
        }
        _ => {}
    }
    mappings.push(ProgramCounterMapping {
        generated_start,
        generated_end,
        logical_address,
    });
}

// iced treats a memory target equal to an input instruction IP as a reference
// to that instruction's relocated copy. Memory operands must instead retain
// their application addresses, even when they point at an instruction head.
// Rename those encoder identities and only their direct control-flow references.
// An observing entry is also external: a backedge must revisit the live patch
// site, running the hook again while active and original code while inactive.
// Its relocated instruction therefore gets a distinct identity, but branches
// retain their application-entry target rather than following that identity.
// The original instructions remain untouched for logical-PC mapping.
fn relocation_encoder_instructions(
    instructions: &[Instruction],
    observing_entry: Option<u64>,
) -> Result<Vec<Instruction>, TrampolineError> {
    let mut normalized = instructions.to_vec();
    let mut next_identity = 0_u32;
    for (index, original) in instructions.iter().enumerate() {
        let is_observing_entry = observing_entry == Some(original.ip());
        if !is_observing_entry
            && !instructions.iter().any(|instruction| {
                instruction.is_ip_rel_memory_operand()
                    && instruction.ip_rel_memory_address() == original.ip()
            })
        {
            continue;
        }
        // Low identities fit every near-branch operand width. Advancing this
        // cursor also excludes all previously assigned identities. The original
        // addresses and external targets must never acquire an accidental label.
        let identity = loop {
            let identity = u16::try_from(next_identity)
                .map_err(|_| encoding_error("no unused encoder instruction identity"))?;
            next_identity += 1;
            if !instructions.iter().any(|instruction| {
                let candidate = u64::from(identity);
                instruction.ip() == candidate
                    || (instruction.is_ip_rel_memory_operand()
                        && instruction.ip_rel_memory_address() == candidate)
                    || (matches!(
                        instruction.op0_kind(),
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                    ) && instruction.near_branch_target() == candidate)
            }) {
                break identity;
            }
        };
        normalized[index].set_ip(u64::from(identity));
        if is_observing_entry {
            continue;
        }
        for instruction in &mut normalized {
            if instruction.near_branch_target() != original.ip() {
                continue;
            }
            match instruction.op0_kind() {
                OpKind::NearBranch16 => instruction.set_near_branch16(identity),
                OpKind::NearBranch32 => instruction.set_near_branch32(u32::from(identity)),
                OpKind::NearBranch64 => instruction.set_near_branch64(u64::from(identity)),
                _ => {}
            }
        }
    }
    Ok(normalized)
}

// A block encoder appends aligned pointer data after its instructions. A far
// conditional branch's fallthrough, or a far CALL's return, must not enter that
// data. Reserve a fixed-width terminal E9 *inside* the encoded block, then patch
// its displacement to the existing return stub after the complete buffer.
// No bytes are inserted after encoding: all RIP-relative fixups retain their
// encoder-computed locations. Blocks without pointer data keep their layout.
struct RelocatedBlock {
    encoded: BlockEncoderResult,
    terminal_jump_offset: Option<usize>,
    branch_relays: Vec<BranchRelay>,
}

struct BranchRelay {
    offset: usize,
    target: u64,
}

fn checked_branch_relay_layout(
    address: u64,
    encoded_len: usize,
    target_count: usize,
    terminal_end: usize,
) -> Result<(usize, i32), TrampolineError> {
    let relay_bytes = target_count
        .checked_mul(BRANCH_RELAY_BYTES)
        .ok_or_else(|| encoding_error("branch relay length overflow"))?;
    let final_len = encoded_len
        .checked_add(relay_bytes)
        .ok_or_else(|| encoding_error("relocated block length overflow"))?;
    let final_len_u64 = u64::try_from(final_len)
        .map_err(|_| TrampolineError::AddressNotRepresentable { address })?;
    address
        .checked_add(final_len_u64)
        .ok_or(TrampolineError::AddressNotRepresentable { address })?;
    let data_len = final_len
        .checked_sub(terminal_end)
        .ok_or_else(|| encoding_error("terminal jump exceeds encoded block"))?;
    let displacement = i32::try_from(data_len)
        .map_err(|_| encoding_error("encoder literal table exceeds signed rel32 reach"))?;
    Ok((final_len, displacement))
}

// iced emits a tracked indirect transfer when a direct branch exceeds rel32
// reach. The original direct destination is not required to begin with ENDBR64.
// Preserve iced's code and pointer locations, redirecting every final Offset64
// branch slot through one ENDBR64 / NOTRACK relay per distinct destination.
// Appending after the literal pool lets the existing terminal jump skip all
// relay code and data.
fn append_branch_relays(
    encoded: &mut BlockEncoderResult,
    address: u64,
    terminal_end: usize,
) -> Result<Vec<BranchRelay>, TrampolineError> {
    let mut branch_literals = Vec::new();
    for info in &encoded.reloc_infos {
        if info.kind != RelocKind::Offset64 {
            continue;
        }
        let offset = info
            .address
            .checked_sub(address)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or_else(|| encoding_error("branch literal precedes encoded block"))?;
        let end = offset
            .checked_add(core::mem::size_of::<u64>())
            .ok_or_else(|| encoding_error("branch literal range overflow"))?;
        if offset < terminal_end {
            return Err(encoding_error(
                "encoder branch literal overlaps executable instructions",
            ));
        }
        let bytes = encoded
            .code_buffer
            .get(offset..end)
            .ok_or_else(|| encoding_error("branch literal exceeds encoded block"))?;
        branch_literals.push((offset, u64::from_le_bytes(bytes.try_into().unwrap())));
    }
    if branch_literals.is_empty() {
        return Ok(Vec::new());
    }

    let mut targets = Vec::new();
    for &(_, target) in &branch_literals {
        if !targets.contains(&target) {
            targets.push(target);
        }
    }

    let (final_len, _) = checked_branch_relay_layout(
        address,
        encoded.code_buffer.len(),
        targets.len(),
        terminal_end,
    )?;

    let mut branch_relays = Vec::with_capacity(targets.len());
    for target in targets {
        let offset = encoded.code_buffer.len();
        let offset_u64 = u64::try_from(offset)
            .map_err(|_| TrampolineError::AddressNotRepresentable { address })?;
        address
            .checked_add(offset_u64)
            .ok_or(TrampolineError::AddressNotRepresentable { address })?;
        encoded.code_buffer.extend_from_slice(&BRANCH_RELAY_CODE);
        encoded.code_buffer.extend_from_slice(&target.to_le_bytes());
        branch_relays.push(BranchRelay { offset, target });
    }
    debug_assert_eq!(encoded.code_buffer.len(), final_len);

    for (offset, target) in branch_literals {
        let relay = branch_relays
            .iter()
            .find(|relay| relay.target == target)
            .ok_or_else(|| encoding_error("missing branch relay for frozen target"))?;
        let relay_offset = u64::try_from(relay.offset)
            .map_err(|_| TrampolineError::AddressNotRepresentable { address })?;
        let relay_address = address
            .checked_add(relay_offset)
            .ok_or(TrampolineError::AddressNotRepresentable { address })?;
        encoded.code_buffer[offset..offset + core::mem::size_of::<u64>()]
            .copy_from_slice(&relay_address.to_le_bytes());
    }
    Ok(branch_relays)
}

fn encode_relocated_block(
    instructions: &[Instruction],
    address: u64,
    observing_entry: Option<u64>,
) -> Result<RelocatedBlock, TrampolineError> {
    encode_relocated_block_with_metadata(instructions, address, observing_entry, false)
}

fn encode_relocated_block_with_metadata(
    instructions: &[Instruction],
    address: u64,
    observing_entry: Option<u64>,
    artifact: bool,
) -> Result<RelocatedBlock, TrampolineError> {
    let normalized = relocation_encoder_instructions(instructions, observing_entry)?;
    let instructions = normalized.as_slice();
    let options = BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS
        | BlockEncoderOptions::RETURN_RELOC_INFOS
        | if artifact {
            BlockEncoderOptions::RETURN_CONSTANT_OFFSETS
        } else {
            0
        };
    let mut encoded =
        BlockEncoder::encode(64, InstructionBlock::new(instructions, address), options)
            .map_err(encoding_error)?;
    if artifact && !encoded.reloc_infos.is_empty() {
        return Err(artifact_error(
            "absolute iced branch literals require a qualified PIC bridge",
        ));
    }
    if encoded.reloc_infos.is_empty() {
        return Ok(RelocatedBlock {
            encoded,
            terminal_jump_offset: None,
            branch_relays: Vec::new(),
        });
    }

    const TERMINAL_JUMP: [u8; NEAR_RETURN_JUMP_BYTES] = [0xE9, 0, 0, 0, 0];
    let mut terminal = Instruction::with_declare_byte(&TERMINAL_JUMP).map_err(encoding_error)?;
    // Give this encoder directive an unused original IP. Otherwise the encoder
    // could redirect an application branch or RIP-relative operand to it.
    // Each displaced instruction excludes at most three values, so this search
    // ends after at most three times the number of instructions plus one.
    let mut terminal_ip = 0_u64;
    while instructions.iter().any(|instruction| {
        instruction.ip() == terminal_ip
            || instruction.near_branch_target() == terminal_ip
            || (instruction.is_ip_rel_memory_operand()
                && instruction.ip_rel_memory_address() == terminal_ip)
    }) {
        terminal_ip = terminal_ip
            .checked_add(1)
            .ok_or_else(|| encoding_error("no unused terminal instruction IP"))?;
    }
    terminal.set_ip(terminal_ip);
    let mut terminated = instructions.to_vec();
    terminated.push(terminal);
    encoded = BlockEncoder::encode(64, InstructionBlock::new(&terminated, address), options)
        .map_err(encoding_error)?;
    // DeclareByte is a fixed-size encoder directive, not an optimizable branch.
    // Its returned offset is the executable/data boundary, without decoding any
    // pointer bytes (which can themselves look like valid instructions).
    let offset = encoded
        .new_instruction_offsets
        .pop()
        .filter(|offset| *offset != u32::MAX)
        .ok_or_else(|| encoding_error("missing terminal jump offset"))? as usize;
    let end = offset
        .checked_add(TERMINAL_JUMP.len())
        .ok_or_else(|| encoding_error("terminal jump offset overflow"))?;
    if encoded.code_buffer.get(offset..end) != Some(TERMINAL_JUMP.as_slice()) {
        return Err(encoding_error(
            "terminal jump reservation was not preserved",
        ));
    }
    address
        .checked_add(encoded.code_buffer.len() as u64)
        .ok_or(TrampolineError::AddressNotRepresentable { address })?;
    let end_address = address
        .checked_add(
            u64::try_from(end).map_err(|_| TrampolineError::AddressNotRepresentable { address })?,
        )
        .ok_or(TrampolineError::AddressNotRepresentable { address })?;
    if encoded
        .reloc_infos
        .iter()
        .any(|info| info.address < end_address)
    {
        return Err(encoding_error(
            "encoder literal overlaps executable instructions",
        ));
    }
    let branch_relays = append_branch_relays(&mut encoded, address, end)?;
    let data_len = encoded
        .code_buffer
        .len()
        .checked_sub(end)
        .ok_or_else(|| encoding_error("terminal jump exceeds encoded block"))?;
    let displacement = i32::try_from(data_len)
        .map_err(|_| encoding_error("encoder literal table exceeds signed rel32 reach"))?;
    encoded.code_buffer[offset + 1..end].copy_from_slice(&displacement.to_le_bytes());
    Ok(RelocatedBlock {
        encoded,
        terminal_jump_offset: Some(offset),
        branch_relays,
    })
}

fn append_relocated_program_counter_mappings(
    mappings: &mut Vec<ProgramCounterMapping>,
    instruction_boundaries: &mut Vec<(u64, u64)>,
    relocated_address: u64,
    code: &[u8],
    instructions: &[Instruction],
    offsets: &[u32],
    observing_entry: Option<u64>,
) -> Result<(), TrampolineError> {
    debug_assert_eq!(instructions.len(), offsets.len());
    // Expanded-instruction sizing must use the same identities as emission:
    // an entry backedge can expand even though its original self-loop cannot.
    let normalized = relocation_encoder_instructions(instructions, observing_entry)?;
    let mut cursor = 0_usize;
    let mut index = 0_usize;
    while index < instructions.len() {
        let offset = offsets[index];
        if offset == u32::MAX {
            let instruction_address = relocated_address + cursor as u64;
            instruction_boundaries.push((instructions[index].ip(), instruction_address));
            let separately_encoded = BlockEncoder::encode(
                64,
                InstructionBlock::new(&normalized[index..=index], instruction_address),
                BlockEncoderOptions::RETURN_RELOC_INFOS,
            )
            .map_err(encoding_error)?;
            let data_start = separately_encoded
                .reloc_infos
                .iter()
                .map(|relocation| relocation.address.saturating_sub(instruction_address))
                .min()
                .and_then(|len| usize::try_from(len).ok())
                .unwrap_or(separately_encoded.code_buffer.len());
            let mut decoder = Decoder::with_ip(
                64,
                &separately_encoded.code_buffer[..data_start],
                instruction_address,
                DecoderOptions::NONE,
            );
            let mut emitted_len = 0_usize;
            while decoder.can_decode() {
                let generated = decoder.decode();
                emitted_len += generated.len();
                if matches!(generated.mnemonic(), Mnemonic::Jmp | Mnemonic::Call)
                    && generated.op0_kind() == OpKind::Memory
                {
                    break;
                }
            }
            if emitted_len == 0 {
                emitted_len = data_start;
            }
            let instruction_end = cursor.saturating_add(emitted_len).min(code.len());
            push_program_counter_mapping(
                mappings,
                instruction_address,
                relocated_address + instruction_end as u64,
                instructions[index].ip(),
            );
            cursor = instruction_end;
            index += 1;
            continue;
        }

        let instruction_start = offset as usize;
        instruction_boundaries.push((
            instructions[index].ip(),
            relocated_address + instruction_start as u64,
        ));
        if cursor < instruction_start {
            let logical_address = instructions[index.saturating_sub(1)].ip();
            push_program_counter_mapping(
                mappings,
                relocated_address + cursor as u64,
                relocated_address + instruction_start as u64,
                logical_address,
            );
        }
        let mut decoder = Decoder::with_ip(
            64,
            &code[instruction_start..],
            relocated_address + instruction_start as u64,
            DecoderOptions::NONE,
        );
        let emitted_len = decoder.decode().len();
        let instruction_end = instruction_start
            .saturating_add(emitted_len)
            .min(code.len());
        push_program_counter_mapping(
            mappings,
            relocated_address + instruction_start as u64,
            relocated_address + instruction_end as u64,
            instructions[index].ip(),
        );
        cursor = instruction_end;
        index += 1;
    }
    if cursor < code.len() {
        let logical_address = instructions
            .last()
            .map_or(relocated_address, Instruction::ip);
        push_program_counter_mapping(
            mappings,
            relocated_address + cursor as u64,
            relocated_address + code.len() as u64,
            logical_address,
        );
    }
    Ok(())
}

// Artifact fields are captured at producer-owned instruction/directive indices.
// This is not a scan for integers that happen to resemble process addresses.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct InstrumentationEmission {
    bytes: Vec<u8>,
    fields: Vec<Fixup>,
}

fn artifact_error(message: &str) -> TrampolineError {
    TrampolineError::Artifact {
        reason: crate::emission::ArtifactRefusalKind::UnmodelledEncoding,
        message: message.into(),
    }
}

fn artifact_fixup_error(error: fixups::Error) -> TrampolineError {
    let reason = match error {
        fixups::Error::DisplacementOutOfRange { .. } => {
            crate::emission::ArtifactRefusalKind::OutOfRange
        }
        fixups::Error::RequiresRuntimeAbsoluteFixup { .. } => {
            crate::emission::ArtifactRefusalKind::RuntimeAbsoluteFixup
        }
        fixups::Error::CrossBiasDomain { .. } | fixups::Error::UnresolvedSymbol(_) => {
            crate::emission::ArtifactRefusalKind::TargetBinding
        }
        _ => crate::emission::ArtifactRefusalKind::InvalidFieldLedger,
    };
    TrampolineError::Artifact {
        reason,
        message: format!("{error:?}"),
    }
}

fn artifact_target(input: &ArtifactEmission, address: u64) -> Target {
    Target::Address(RelativeAddress {
        domain: BiasDomain(input.profile().bias_domain()),
        offset: i128::from(address),
    })
}

fn append_artifact_original_fields(
    fields: &mut Vec<Fixup>,
    input: &ArtifactEmission,
    address: u64,
    block: &BlockEncoderResult,
    originals: &[(usize, Instruction)],
    entries: &[(u64, u64)],
) -> Result<(), TrampolineError> {
    for &(index, original) in originals {
        let branch = matches!(
            original.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        );
        let rip = original.is_ip_rel_memory_operand();
        // A SIB index does not make a base-less disp32 load-bias invariant.
        // Until its address contribution has an explicit runtime fixup, retain
        // the required refusal rather than omitting a known address field.
        if original.op_kinds().any(|kind| kind == OpKind::Memory)
            && !rip
            && original.memory_base() == iced_x86::Register::None
            && original.memory_index() != iced_x86::Register::None
        {
            return Err(TrampolineError::Artifact {
                reason: crate::emission::ArtifactRefusalKind::RuntimeAbsoluteFixup,
                message: "base-less indexed memory needs explicit displacement provenance and a runtime fixup".into(),
            });
        }
        let absolute = original.op_kinds().any(|kind| kind == OpKind::Memory)
            && !rip
            && original.memory_base() == iced_x86::Register::None
            && original.memory_index() == iced_x86::Register::None;
        if !branch && !rip && !absolute {
            continue;
        }
        if (branch && original.op0_kind() != OpKind::NearBranch64)
            || (rip && original.memory_base() != iced_x86::Register::RIP)
        {
            return Err(artifact_error(
                "truncated-address branch or EIP operand lacks a common-bias proof",
            ));
        }
        let offset = block
            .new_instruction_offsets
            .get(index)
            .copied()
            .filter(|offset| *offset != u32::MAX)
            .ok_or_else(|| {
                artifact_error("expanded original address operand needs an explicit PIC bridge")
            })? as usize;
        let generated = address
            .checked_add(offset as u64)
            .ok_or(TrampolineError::AddressNotRepresentable { address })?;
        let tail = block
            .code_buffer
            .get(offset..)
            .ok_or_else(|| artifact_error("encoder instruction offset exceeds image"))?;
        let decoded = Decoder::with_ip(64, tail, generated, DecoderOptions::NONE).decode();
        if decoded.is_invalid() {
            return Err(artifact_error(
                "encoder-owned original instruction is invalid",
            ));
        }
        let constants = block
            .constant_offsets
            .get(index)
            .ok_or_else(|| artifact_error("encoder omitted original constant offsets"))?;
        let (local, width, target, role) = if branch {
            if decoded.op0_kind() != OpKind::NearBranch64 {
                return Err(artifact_error(
                    "original branch is no longer a single direct branch",
                ));
            }
            let internal = entries
                .iter()
                .find(|(pc, _)| *pc == original.near_branch_target());
            let target =
                internal.map_or(original.near_branch_target(), |(_, generated)| *generated);
            if decoded.near_branch_target() != target {
                return Err(artifact_error(
                    "encoder branch target differs from explicit entry routing",
                ));
            }
            let target = match internal {
                Some(_) => Target::Image {
                    image: ImageId(address),
                    offset: target
                        .checked_sub(address)
                        .ok_or_else(|| artifact_error("internal branch target precedes image"))?,
                },
                None => artifact_target(input, target),
            };
            (
                constants.immediate_offset(),
                constants.immediate_size(),
                target,
                Role::OriginalBranch {
                    original_pc: original.ip(),
                },
            )
        } else if rip {
            if decoded.memory_base() != iced_x86::Register::RIP
                || decoded.ip_rel_memory_address() != original.ip_rel_memory_address()
            {
                return Err(artifact_error("encoder changed original RIP data identity"));
            }
            (
                constants.displacement_offset(),
                constants.displacement_size(),
                artifact_target(input, original.ip_rel_memory_address()),
                Role::OriginalRipOperand {
                    original_pc: original.ip(),
                },
            )
        } else {
            (
                constants.displacement_offset(),
                constants.displacement_size(),
                artifact_target(input, original.memory_displacement64()),
                Role::OriginalAbsoluteOperand {
                    original_pc: original.ip(),
                },
            )
        };
        let next = offset
            .checked_add(decoded.len())
            .ok_or_else(|| artifact_error("original instruction end overflow"))?
            as u64;
        let encoding = match (absolute, width) {
            (true, 8) => Encoding::Absolute64,
            (false, 1) if branch => Encoding::PcRelative8 { next },
            (false, 4) => Encoding::PcRelative32 { next },
            _ => {
                return Err(artifact_error(
                    "original operand has unsupported relative width",
                ));
            }
        };
        if local
            .checked_add(width)
            .is_none_or(|end| end > decoded.len())
        {
            return Err(artifact_error(
                "encoder operand field exceeds original instruction",
            ));
        }
        let field_offset = offset
            .checked_add(local)
            .ok_or_else(|| artifact_error("original field offset overflow"))?;
        let end = field_offset
            .checked_add(width)
            .ok_or_else(|| artifact_error("original field extent overflow"))?;
        let expected = block
            .code_buffer
            .get(field_offset..end)
            .ok_or_else(|| artifact_error("original field exceeds image"))?
            .to_vec();
        fields.push(Fixup {
            offset: field_offset as u64,
            encoding,
            target,
            role,
            expected,
        });
    }
    Ok(())
}

fn artifact_metadata(
    input: &ArtifactEmission,
    address: u64,
    fields: &[Fixup],
    has_hook: bool,
) -> Result<ArtifactImageMetadata, TrampolineError> {
    let fields = fields
        .iter()
        .map(|field| {
            let (encoding, origin) = match field.encoding {
                Encoding::PcRelative8 { next } | Encoding::PcRelative32 { next } => {
                    (ArtifactFieldEncoding::Relative, next)
                }
                Encoding::Delta64 { anchor } => (ArtifactFieldEncoding::Delta, anchor),
                Encoding::Absolute64 => {
                    return Err(artifact_error("absolute field escaped artifact linking"));
                }
            };
            let target = match field.target {
                Target::Address(target) => target,
                Target::Image { image, offset } if image == ImageId(address) => RelativeAddress {
                    domain: BiasDomain(input.profile().bias_domain()),
                    offset: i128::from(address) + i128::from(offset),
                },
                _ => {
                    return Err(artifact_error(
                        "unresolved image/symbol escaped artifact linking",
                    ));
                }
            };
            Ok(ArtifactField {
                offset: field.offset,
                width: field.encoding.width(),
                encoding,
                origin,
                target: target.offset,
                bias_domain: target.domain.0,
                role: format!("{:?}", field.role),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut requirements = vec![
        ArtifactRequirement::ArtifactIdentityAndAddressBinding,
        ArtifactRequirement::TargetCpuAndStateAtEntry,
        ArtifactRequirement::OriginalDynamicRelocationOwnership,
        ArtifactRequirement::OriginalImmediatePointerProvenance,
        ArtifactRequirement::GeneratedUnwindInformation,
        ArtifactRequirement::OriginalCodeAsDataContract,
    ];
    if has_hook {
        requirements.push(ArtifactRequirement::HookAbiAndReadiness(
            input.hook().identity,
        ));
    }
    Ok(ArtifactImageMetadata {
        fields,
        requirements,
    })
}

/// Process-lifetime dual-mapped trampoline storage prepared before instrumentation.
///
/// An arena keeps separate RW and RX aliases to the same backing pages and
/// reserves fixed-size slots without issuing syscalls. This avoids an RWX VMA,
/// but it is not strict W^X because executable bytes remain writable through
/// the separate RW alias. Clients that need a stronger write-after-publish
/// boundary must not use this arena API.
///
/// Fork-related processes share the reservation cursor and the configured slot
/// budget. A separate non-executable shared metadata page prevents their code
/// publications from reusing the same slot after a copy-on-write fork. That
/// page, like the code aliases, remains mapped for the process lifetime.
pub struct TrampolineArena {
    writable: *mut u8,
    executable: *mut u8,
    len: usize,
    next: *const AtomicUsize,
    reservation_len: usize,
}

// SAFETY: the initialized cursor is process-shared, slots are reserved atomically
// and never reused, and all three mappings live for the process lifetime.
unsafe impl Send for TrampolineArena {}
// SAFETY: see Send; writers receive disjoint slots before publishing bytes.
unsafe impl Sync for TrampolineArena {}

impl TrampolineArena {
    /// Allocates process-lifetime trampoline slots near an address.
    pub fn allocate_near(address: u64, slots: usize) -> Result<Self, TrampolineError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (address, slots);
            return Err(TrampolineError::UnsupportedPlatform);
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            if slots == 0 {
                return Err(TrampolineError::InvalidArenaCapacity);
            }
            let len = slots
                .checked_mul(TRAMPOLINE_ALLOCATION_BYTES)
                .ok_or(TrampolineError::InvalidArenaCapacity)?;
            PendingMapping::allocate_near_len(address, len)?.into_arena()
        }
    }

    /// Returns whether every slot in this arena is reachable from an address.
    pub fn can_reach(&self, address: u64) -> bool {
        let Some(next_ip) = address.checked_add(crate::patcher::NEAR_JUMP_BYTES as u64) else {
            return false;
        };
        let start = self.executable as usize as u64;
        let Some(end) = start.checked_add(self.len.saturating_sub(1) as u64) else {
            return false;
        };
        i32::try_from(i128::from(start) - i128::from(next_ip)).is_ok()
            && i32::try_from(i128::from(end) - i128::from(next_ip)).is_ok()
    }

    /// Returns the process-lifetime RW code alias.
    pub fn writable_range(&self) -> core::ops::Range<usize> {
        let start = self.writable as usize;
        start..start + self.len
    }

    /// Returns the process-lifetime RX code alias.
    pub fn executable_range(&self) -> core::ops::Range<usize> {
        let start = self.executable as usize;
        start..start + self.len
    }

    /// Returns the process-shared reservation-cursor page.
    pub fn reservation_range(&self) -> core::ops::Range<usize> {
        let start = self.next as usize;
        start..start + self.reservation_len
    }

    /// Emits one checked static plan into a freshly reserved arena slot.
    ///
    /// Observing controls use process-local Arc storage, while these slots can
    /// be published by a different fork-related process. Controlled plans are
    /// refused before slot reservation; use private or sealed-grouped mappings.
    pub fn allocate(&self, plan: &TrampolinePlan) -> Result<ExecutableTrampoline, TrampolineError> {
        if !plan.controls.is_empty() {
            return Err(TrampolineError::ControlledArenaUnsupported);
        }
        if !self.can_reach(plan.execute_address()) {
            return Err(TrampolineError::NoReachableMapping);
        }
        // SAFETY: successful construction initialized this shared atomic and
        // transferred its mapping to process-lifetime ownership.
        let offset = reserve_arena_slot(unsafe { &*self.next }, self.len)?;
        let address = (self.executable as usize).checked_add(offset).ok_or(
            TrampolineError::AddressNotRepresentable {
                address: self.executable as usize as u64,
            },
        )? as u64;
        let image = plan.emit_at(address)?;
        if image.bytes.len() > TRAMPOLINE_ALLOCATION_BYTES {
            return Err(TrampolineError::CodeTooLarge {
                code_len: image.bytes.len(),
                allocation_len: TRAMPOLINE_ALLOCATION_BYTES,
            });
        }
        // SAFETY: this thread exclusively owns the reserved slot.
        unsafe {
            core::ptr::copy_nonoverlapping(
                image.bytes.as_ptr(),
                self.writable.add(offset),
                image.bytes.len(),
            );
        }
        compiler_fence(Ordering::SeqCst);
        Ok(ExecutableTrampoline {
            address,
            allocation_len: TRAMPOLINE_ALLOCATION_BYTES,
            mapping_address: 0,
            code_len: image.bytes.len(),
            layout: image.layout,
            program_counters: image.program_counters.into_boxed_slice(),
            controls: ManuallyDrop::new(image.controls),
            clock: ManuallyDrop::new(image.clock),
            program_counters_published: AtomicBool::new(false),
        })
    }
}

fn reserve_arena_slot(next: &AtomicUsize, len: usize) -> Result<usize, TrampolineError> {
    // This reserves exclusive storage; it does not publish completed code.
    // Saturation prevents failed reservations from wrapping and reusing bytes.
    let mut offset = next.load(Ordering::Acquire);
    loop {
        let end = offset
            .checked_add(TRAMPOLINE_ALLOCATION_BYTES)
            .filter(|end| *end <= len)
            .ok_or(TrampolineError::ArenaFull)?;
        match next.compare_exchange_weak(offset, end, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(offset),
            Err(observed) => offset = observed,
        }
    }
}

/// Process-lifetime executable trampoline mapping.
///
/// The writable alias is removed before construction returns. The RX page is
/// intentionally not unmapped on drop because another thread may have fetched
/// its address before concurrent deactivation. Observing controls embedded in
/// that code are retained for the same lifetime. After fork, inherited controls
/// are independent snapshots, not process-shared enable state. Do not publish
/// newly created controlled code or heap pointers into another process.
pub struct ExecutableTrampoline {
    address: u64,
    allocation_len: usize,
    mapping_address: u64,
    code_len: usize,
    layout: TrampolineLayout,
    program_counters: Box<[ProgramCounterMapping]>,
    program_counters_published: AtomicBool,
    // Normal handle drop retains executable code and its embedded pointers.
    // Verified unpublished discard releases these references after unmapping;
    // non-reclaimable arena slots retain them for the same process lifetime.
    controls: ManuallyDrop<Vec<ProbeControl>>,
    clock: ManuallyDrop<Option<crate::backedge_clock::BackedgeClock>>,
}

/// Owns a staged executable image until its publication transaction commits.
///
/// No global PC metadata may be published while this guard owns the image.
/// Dropping it releases the RX mapping, including after a later preflight
/// failure. Once source bytes can reach the image, its owner must commit or
/// retain this guard until verified rollback and execution drainage complete.
pub(crate) struct PendingExecutableTrampoline {
    trampoline: Option<ExecutableTrampoline>,
}

impl PendingExecutableTrampoline {
    /// Takes exclusive ownership of an initialized, immutable RX mapping.
    ///
    /// # Safety
    /// `mapping_address..mapping_address + allocation_len` must be one owned
    /// live mapping, contain the complete image at its encoded address, and
    /// have no writable shared aliases. No source entry or global PC metadata
    /// may reference it yet. The caller relinquishes unmapping ownership.
    pub(crate) unsafe fn from_owned_mapping(
        image: &TrampolineImage,
        mapping_address: u64,
        allocation_len: usize,
    ) -> Self {
        debug_assert_ne!(mapping_address, 0);
        debug_assert!(image.address >= mapping_address);
        debug_assert!(
            image.address as u128 + image.bytes.len() as u128
                <= mapping_address as u128 + allocation_len as u128
        );
        Self {
            trampoline: Some(ExecutableTrampoline {
                address: image.address,
                mapping_address,
                allocation_len,
                code_len: image.bytes.len(),
                layout: image.layout,
                program_counters: image.program_counters.clone().into_boxed_slice(),
                controls: ManuallyDrop::new(image.controls.clone()),
                clock: ManuallyDrop::new(image.clock.clone()),
                program_counters_published: AtomicBool::new(false),
            }),
        }
    }

    /// Returns the staged allocation without publishing global PC metadata.
    pub(crate) fn trampoline(&self) -> &ExecutableTrampoline {
        self.trampoline.as_ref().unwrap()
    }

    /// Transfers the initialized mapping to process-lifetime ownership.
    pub(crate) fn commit(mut self) -> ExecutableTrampoline {
        self.trampoline.take().unwrap()
    }
}

impl Drop for PendingExecutableTrampoline {
    fn drop(&mut self) {
        if let Some(trampoline) = self.trampoline.take() {
            trampoline.discard();
        }
    }
}

impl ExecutableTrampoline {
    /// Stages an already-emitted image at its authenticated exact address.
    ///
    /// The returned guard releases its mapping on failure in the surrounding
    /// publication transaction. Its `commit` is infallible; callers publish
    /// global PC mappings only after committing the transaction.
    pub(crate) fn allocate_image_at(
        image: &TrampolineImage,
        address: u64,
    ) -> Result<PendingExecutableTrampoline, TrampolineError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (image, address);
            Err(TrampolineError::UnsupportedPlatform)
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            if image.address != address {
                return Err(encoding_error(
                    "trampoline image was emitted for a different executable address",
                ));
            }
            let page_size = page_size()?;
            let native_address = usize::try_from(address)
                .map_err(|_| TrampolineError::AddressNotRepresentable { address })?;
            let mapping_start = align_down(native_address, page_size);
            let entry_offset = native_address - mapping_start;
            let required = entry_offset
                .checked_add(image.bytes.len())
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let mapping_len = required
                .checked_add(page_size - 1)
                .map(|value| align_down(value, page_size))
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let mapping = PendingMapping::allocate_exact(mapping_start, mapping_len, address)?;
            let trampoline = mapping.publish_at(image, entry_offset)?;
            Ok(PendingExecutableTrampoline {
                trampoline: Some(trampoline),
            })
        }
    }

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
            mapping.publish_at(&image, 0)
        }
    }

    /// Allocates the trampoline at one exact instruction-pun destination.
    ///
    /// The complete emitted image is backed by a fresh RX mapping claimed with
    /// MAP_FIXED_NOREPLACE. Existing mappings are never replaced.
    pub fn allocate_at(plan: &TrampolinePlan, address: u64) -> Result<Self, TrampolineError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (plan, address);
            return Err(TrampolineError::UnsupportedPlatform);
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let image = plan.emit_at(address)?;
            let page_size = page_size()?;
            let native_address = usize::try_from(address)
                .map_err(|_| TrampolineError::AddressNotRepresentable { address })?;
            let mapping_start = align_down(native_address, page_size);
            let entry_offset = native_address - mapping_start;
            let required = entry_offset
                .checked_add(image.bytes.len())
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let mapping_len = required
                .checked_add(page_size - 1)
                .map(|value| align_down(value, page_size))
                .ok_or(TrampolineError::AddressNotRepresentable { address })?;
            let mapping = PendingMapping::allocate_exact(mapping_start, mapping_len, address)?;
            mapping.publish_at(&image, entry_offset)
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

    /// Returns the RIP reported after the optional entry INT3.
    ///
    /// `None` identifies an ordinary trampoline with no tracer-owned stops.
    pub const fn ptrace_entry_stop_rip(&self) -> Option<u64> {
        if self.layout.entry_stop_len == PTRACE_STOP_BYTES.len() {
            Some(
                self.address
                    + self.layout.relocated_prefix_len as u64
                    + PTRACE_STOP_BYTES.len() as u64,
            )
        } else {
            None
        }
    }

    /// Returns the RIP reported after the optional post-restore INT3.
    ///
    /// This is also the first byte of the relocated tail. At this stop every
    /// explicitly saved application GPR, RFLAGS, and extended-state component
    /// is restored, but RSP intentionally remains at the controller-owned stack
    /// top. No relocated application instruction has executed yet.
    pub const fn ptrace_completion_stop_rip(&self) -> Option<u64> {
        if self.layout.completion_stop_len == PTRACE_STOP_BYTES.len() {
            Some(
                self.address
                    + self.layout.relocated_prefix_len as u64
                    + self.layout.entry_stop_len as u64
                    + self.layout.instrumentation_len as u64
                    + self.layout.restore_len as u64
                    + PTRACE_STOP_BYTES.len() as u64,
            )
        } else {
            None
        }
    }

    /// Returns the entry immediately after the first logical hook's restore.
    ///
    /// A signal handler that already emulated a replace-first instruction can
    /// resume here after publishing the hook. The interrupted register context
    /// must already contain the emulated result.
    /// Coalesced images still execute any later logical callbacks. For a
    /// callback-free image this is the instruction's generated entry.
    pub const fn relocated_tail_address(&self) -> u64 {
        self.address
            + self.layout.relocated_prefix_len as u64
            + self.layout.entry_stop_len as u64
            + self.layout.instrumentation_len as u64
            + self.layout.restore_len as u64
            + self.layout.completion_stop_len as u64
    }

    /// Returns the emitted section lengths.
    pub const fn layout(&self) -> TrampolineLayout {
        self.layout
    }

    /// Returns generated ranges and their corresponding application PCs.
    pub fn program_counter_mappings(&self) -> &[ProgramCounterMapping] {
        &self.program_counters
    }

    /// Translates a PC within this trampoline to an application instruction.
    pub fn translate_program_counter(&self, program_counter: u64) -> Option<u64> {
        self.program_counters
            .iter()
            .find_map(|mapping| mapping.translate(program_counter))
    }

    /// Publishes this trampoline to the process-wide reverse-PC lookup.
    ///
    /// Ordinary `InstalledHook` entrypoints call this automatically after
    /// binding succeeds. The controller-owned ptrace-stop entrypoint leaves it
    /// explicit. Direct users of `ExecutableTrampoline::allocate` can call it
    /// after making the trampoline reachable. Publication is idempotent and
    /// process-lifetime.
    pub fn publish_program_counter_mappings(&self) {
        if !self.program_counters_published.swap(true, Ordering::AcqRel) {
            register_program_counter_mappings(&self.program_counters);
        }
    }

    pub(crate) fn discard(self) {
        debug_assert!(!self.program_counters_published.load(Ordering::Relaxed));
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let mut this = self;
            if this.mapping_address != 0 {
                // SAFETY: this unpublished object exclusively owns the RX mapping.
                let unmapped = unsafe {
                    libc::munmap(
                        this.mapping_address as usize as *mut libc::c_void,
                        this.allocation_len,
                    )
                };
                if unmapped == 0 {
                    // SAFETY: this consumed unpublished handle has no reachable
                    // code after unmapping. No other path drops this field.
                    // Failed unmapping conservatively retains controls with code.
                    unsafe { ManuallyDrop::drop(&mut this.controls) };
                    // Same unpublished-unmap proof retires the embedded data owner.
                    unsafe { ManuallyDrop::drop(&mut this.clock) };
                }
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

#[derive(Clone, Copy)]
enum ProgramCounterPublication {
    Automatic,
    Explicit,
}

impl InstalledHook {
    /// Generates and binds an initially inactive observing hook.
    ///
    /// # Safety
    ///
    /// The writable alias in site must satisfy LiveJumpPatch::bind and remain
    /// valid for the process lifetime. Its code and scan must describe the
    /// executable region. The callback must remain callable for the process
    /// lifetime and must not unwind across its C ABI boundary. The caller must
    /// also prove that no direct or indirect control-flow entry can target the
    /// interior of the displaced instruction window.
    pub unsafe fn install(
        site: HookSite<'_>,
        hook: HookCallback,
        staleness: StalenessBudget,
    ) -> Result<Self, TrampolineError> {
        let plan = TrampolinePlan::from_scan(site.scan, site.execute_address, hook)?;
        let trampoline = ExecutableTrampoline::allocate(&plan)?;
        // SAFETY: forwarded from this method's mapping-lifetime contract.
        unsafe {
            Self::bind(
                site,
                plan,
                trampoline,
                Some(staleness),
                ProgramCounterPublication::Automatic,
            )
        }
    }

    /// Generates a hook that replaces the first displaced instruction.
    ///
    /// # Safety
    ///
    /// The same requirements as install apply, including excluding every
    /// interior entry into the displaced window. The callback must implement
    /// the skipped instruction's effects in the mutable HookContext.
    pub unsafe fn install_replacing_first(
        site: HookSite<'_>,
        hook: HookCallback,
        staleness: StalenessBudget,
    ) -> Result<Self, TrampolineError> {
        let plan =
            TrampolinePlan::from_scan_replacing_first(site.scan, site.execute_address, hook)?;
        let trampoline = ExecutableTrampoline::allocate(&plan)?;
        // SAFETY: forwarded from this method's mapping-lifetime contract.
        unsafe {
            Self::bind(
                site,
                plan,
                trampoline,
                Some(staleness),
                ProgramCounterPublication::Automatic,
            )
        }
    }

    /// Generates a quiescent hook that replaces the first displaced instruction.
    ///
    /// The returned hook must be toggled only with
    /// [`Self::activate_quiescent`] and [`Self::deactivate_quiescent`].
    ///
    /// # Safety
    ///
    /// The same mapping and callback requirements as
    /// [`Self::install_replacing_first`] apply. Each quiescent toggle additionally
    /// requires its documented no-other-thread proof.
    pub unsafe fn install_replacing_first_quiescent(
        site: HookSite<'_>,
        hook: HookCallback,
    ) -> Result<Self, TrampolineError> {
        let plan =
            TrampolinePlan::from_scan_replacing_first(site.scan, site.execute_address, hook)?;
        let trampoline = ExecutableTrampoline::allocate(&plan)?;
        // SAFETY: forwarded from this method's mapping-lifetime contract.
        unsafe {
            Self::bind(
                site,
                plan,
                trampoline,
                None,
                ProgramCounterPublication::Automatic,
            )
        }
    }

    /// Generates an observing hook in preallocated trampoline storage.
    ///
    /// # Safety
    ///
    /// The same requirements as install apply. The arena must remain alive
    /// for the process lifetime.
    pub unsafe fn install_in_arena(
        site: HookSite<'_>,
        hook: HookCallback,
        staleness: StalenessBudget,
        arena: &TrampolineArena,
    ) -> Result<Self, TrampolineError> {
        let plan = TrampolinePlan::from_scan(site.scan, site.execute_address, hook)?;
        let trampoline = arena.allocate(&plan)?;
        // SAFETY: forwarded from this method's mapping-lifetime contract.
        unsafe {
            Self::bind(
                site,
                plan,
                trampoline,
                Some(staleness),
                ProgramCounterPublication::Automatic,
            )
        }
    }

    /// Generates a replace-first hook in preallocated trampoline storage.
    ///
    /// # Safety
    ///
    /// The same requirements as install_replacing_first apply. The arena
    /// must remain alive for the process lifetime.
    pub unsafe fn install_replacing_first_in_arena(
        site: HookSite<'_>,
        hook: HookCallback,
        staleness: StalenessBudget,
        arena: &TrampolineArena,
    ) -> Result<Self, TrampolineError> {
        let plan =
            TrampolinePlan::from_scan_replacing_first(site.scan, site.execute_address, hook)?;
        let trampoline = arena.allocate(&plan)?;
        // SAFETY: forwarded from this method's mapping-lifetime contract.
        unsafe {
            Self::bind(
                site,
                plan,
                trampoline,
                Some(staleness),
                ProgramCounterPublication::Automatic,
            )
        }
    }

    /// Generates a quiescent replace-first hook in preallocated storage.
    ///
    /// The returned hook must be toggled only with
    /// [`Self::activate_quiescent`] and [`Self::deactivate_quiescent`].
    ///
    /// # Safety
    ///
    /// The same requirements as [`Self::install_replacing_first_in_arena`]
    /// apply. Each quiescent toggle additionally requires its documented
    /// no-other-thread proof.
    pub unsafe fn install_replacing_first_in_arena_quiescent(
        site: HookSite<'_>,
        hook: HookCallback,
        arena: &TrampolineArena,
    ) -> Result<Self, TrampolineError> {
        let plan =
            TrampolinePlan::from_scan_replacing_first(site.scan, site.execute_address, hook)?;
        let trampoline = arena.allocate(&plan)?;
        // SAFETY: forwarded from this method's mapping-lifetime contract.
        unsafe {
            Self::bind(
                site,
                plan,
                trampoline,
                None,
                ProgramCounterPublication::Automatic,
            )
        }
    }

    /// Generates a quiescent replace-first hook bracketed by tracer stops.
    ///
    /// The returned hook must be toggled only with
    /// [`Self::activate_quiescent`] and [`Self::deactivate_quiescent`]. Its
    /// entry and completion INT3 instructions must be authenticated and
    /// suppressed by an external ptrace controller on every execution.
    ///
    /// # Safety
    ///
    /// The same requirements as [`Self::install_replacing_first_in_arena`]
    /// apply. Each quiescent toggle additionally requires its documented
    /// no-other-thread proof, and the caller must guarantee that the controller
    /// owns both generated breakpoint stops before this hook becomes reachable.
    /// This controller-owned mode does not publish process-global reverse-PC
    /// metadata automatically. A caller that needs the global lookup must call
    /// [`ExecutableTrampoline::publish_program_counter_mappings`] explicitly
    /// after binding and retain its process-lifetime publication semantics.
    pub unsafe fn install_replacing_first_in_arena_quiescent_with_ptrace_stops(
        site: HookSite<'_>,
        hook: HookCallback,
        arena: &TrampolineArena,
    ) -> Result<Self, TrampolineError> {
        let plan = TrampolinePlan::from_scan_replacing_first_with_ptrace_stops(
            site.scan,
            site.execute_address,
            hook,
        )?;
        let trampoline = arena.allocate(&plan)?;
        // SAFETY: forwarded from this method's mapping-lifetime contract.
        unsafe {
            Self::bind(
                site,
                plan,
                trampoline,
                None,
                ProgramCounterPublication::Explicit,
            )
        }
    }

    unsafe fn bind(
        site: HookSite<'_>,
        trampoline_plan: TrampolinePlan,
        trampoline: ExecutableTrampoline,
        staleness: Option<StalenessBudget>,
        publication: ProgramCounterPublication,
    ) -> Result<Self, TrampolineError> {
        let patch_plan = match JumpPatchPlan::from_scan(
            site.scanner,
            site.scan,
            site.code,
            site.region_base,
            site.execute_address,
            trampoline.address,
        ) {
            Ok(plan) if plan.displaced_len() == trampoline_plan.displaced_len() => plan,
            Ok(_) => {
                trampoline.discard();
                return Err(PatchError::RegionMismatch {
                    address: site.execute_address,
                }
                .into());
            }
            Err(error) => {
                trampoline.discard();
                return Err(error.into());
            }
        };
        // SAFETY: forwarded from the public installation method.
        let patch = match unsafe {
            if let Some(staleness) = staleness {
                LiveJumpPatch::bind(patch_plan, site.writable_address, staleness)
            } else {
                LiveJumpPatch::bind_quiescent(patch_plan, site.writable_address)
            }
        } {
            Ok(patch) => patch,
            Err(error) => {
                trampoline.discard();
                return Err(error.into());
            }
        };
        if matches!(publication, ProgramCounterPublication::Automatic) {
            trampoline.publish_program_counter_mappings();
        }
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

    /// Returns the number of concurrent-publication guard traps handled.
    pub fn handled_guard_traps(&self) -> u64 {
        self.patch.handled_guard_traps()
    }

    /// Activates the hook, returning whether code bytes changed.
    pub fn activate(&self) -> Result<bool, TrampolineError> {
        self.activate_with(|| {
            // SAFETY: install captured the concurrent binding contract.
            unsafe { self.patch.apply() }
        })
    }

    /// Activates the hook without concurrent-reader publication protection.
    ///
    /// # Safety
    ///
    /// No other process thread, signal handler, or code writer may fetch, read,
    /// or modify the patch window until this call returns.
    pub unsafe fn activate_quiescent(&self) -> Result<bool, TrampolineError> {
        self.activate_with(|| {
            // SAFETY: forwarded from this method's caller-verified quiescence.
            unsafe { self.patch.apply_quiescent() }
        })
    }

    fn activate_with(
        &self,
        publish: impl FnOnce() -> Result<(), PatchError>,
    ) -> Result<bool, TrampolineError> {
        match self.state.compare_exchange(
            STATE_INACTIVE,
            STATE_TRANSITIONING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => match publish() {
                Ok(()) => {
                    self.state.store(STATE_ACTIVE, Ordering::Release);
                    Ok(true)
                }
                Err(error) => {
                    self.state.store(STATE_INACTIVE, Ordering::Release);
                    Err(error.into())
                }
            },
            Err(STATE_ACTIVE) => Ok(false),
            Err(_) => Err(TrampolineError::TransitionInProgress),
        }
    }

    /// Deactivates the hook, returning whether code bytes changed.
    pub fn deactivate(&self) -> Result<bool, TrampolineError> {
        self.deactivate_with(|| {
            // SAFETY: install captured the concurrent binding contract.
            unsafe { self.patch.revert() }
        })
    }

    /// Deactivates the hook without concurrent-reader publication protection.
    ///
    /// # Safety
    ///
    /// The same quiescence proof as [`Self::activate_quiescent`] is required.
    pub unsafe fn deactivate_quiescent(&self) -> Result<bool, TrampolineError> {
        self.deactivate_with(|| {
            // SAFETY: forwarded from this method's caller-verified quiescence.
            unsafe { self.patch.revert_quiescent() }
        })
    }

    fn deactivate_with(
        &self,
        publish: impl FnOnce() -> Result<(), PatchError>,
    ) -> Result<bool, TrampolineError> {
        match self.state.compare_exchange(
            STATE_ACTIVE,
            STATE_TRANSITIONING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => match publish() {
                Ok(()) => {
                    self.state.store(STATE_INACTIVE, Ordering::Release);
                    Ok(true)
                }
                Err(error) => {
                    self.state.store(STATE_ACTIVE, Ordering::Release);
                    Err(error.into())
                }
            },
            Err(STATE_INACTIVE) => Ok(false),
            Err(_) => Err(TrampolineError::TransitionInProgress),
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct PendingReservation {
    address: *mut AtomicUsize,
    len: usize,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl PendingReservation {
    fn new() -> Result<Self, TrampolineError> {
        let len = page_size()?;
        // SAFETY: a fresh page-aligned shared mapping is large enough for the
        // atomic. It has no executable alias and no owner can see it yet.
        let address = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(os_error("mmap shared arena reservation"));
        }
        let address = address.cast::<AtomicUsize>();
        // SAFETY: this constructor uniquely owns aligned, writable storage.
        unsafe { address.write(AtomicUsize::new(0)) };
        Ok(Self { address, len })
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for PendingReservation {
    fn drop(&mut self) {
        // SAFETY: the guard still owns this unpublished metadata mapping.
        unsafe { libc::munmap(self.address.cast(), self.len) };
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
const ARENA_REQUIRED_SEALS: libc::c_int =
    libc::F_SEAL_FUTURE_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn seal_arena_backing(fd: libc::c_int) -> Result<(), TrampolineError> {
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, ARENA_REQUIRED_SEALS) } != 0 {
        return Err(os_error("seal trampoline arena memfd"));
    }
    let observed_seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if observed_seals != ARENA_REQUIRED_SEALS {
        return Err(TrampolineError::BackingStore {
            operation: "verify trampoline arena memfd seals",
            errno: if observed_seals < 0 {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            } else {
                libc::EIO
            },
        });
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl PendingMapping {
    fn new(len: usize) -> Result<Self, TrampolineError> {
        let name = b"liteinst2-trampoline\0";
        // SAFETY: valid NUL-terminated name and supported memfd flags.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr().cast::<libc::c_char>(),
                libc::MFD_CLOEXEC | 0x0002, // MFD_ALLOW_SEALING
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
        Ok(mapping)
    }

    fn try_map_executable(&mut self, address: usize) -> bool {
        // SAFETY: MAP_FIXED_NOREPLACE never replaces an existing VMA.
        let executable = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                self.len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                self.fd,
                0,
            )
        };
        if executable == libc::MAP_FAILED {
            return false;
        }
        if executable as usize != address {
            // SAFETY: executable is the mapping just returned by mmap.
            unsafe { libc::munmap(executable, self.len) };
            return false;
        }
        self.executable = executable;
        true
    }

    fn allocate_exact(
        mapping_start: usize,
        len: usize,
        entry_address: u64,
    ) -> Result<Self, TrampolineError> {
        let mut mapping = Self::new(len)?;
        if !mapping.try_map_executable(mapping_start) {
            return Err(TrampolineError::ExactAddressUnavailable {
                address: entry_address,
            });
        }
        Ok(mapping)
    }

    fn allocate_near(execute_address: u64) -> Result<Self, TrampolineError> {
        let page_size = page_size()?;
        let len = TRAMPOLINE_ALLOCATION_BYTES.max(page_size);
        Self::allocate_near_len(execute_address, len)
    }

    fn allocate_near_len(execute_address: u64, len: usize) -> Result<Self, TrampolineError> {
        let page_size = page_size()?;
        let len = len
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or(TrampolineError::InvalidPageSize)?;
        let mut mapping = Self::new(len)?;
        let next_ip = execute_address
            .checked_add(crate::patcher::NEAR_JUMP_BYTES as u64)
            .ok_or(TrampolineError::AddressNotRepresentable {
                address: execute_address,
            })?;
        for candidate in near_candidates(next_ip, len, page_size)? {
            if mapping.try_map_executable(candidate) {
                return Ok(mapping);
            }
        }
        Err(TrampolineError::NoReachableMapping)
    }

    fn into_arena(mut self) -> Result<TrampolineArena, TrampolineError> {
        let next = PendingReservation::new()?;
        // FUTURE_WRITE preserves the existing RW alias while preventing any
        // subsequently reopened descriptor or mapping from changing the code
        // backing. Geometry and policy are then locked for the arena lifetime.
        seal_arena_backing(self.fd)?;
        // Linux may release a descriptor even when close reports an error.
        // Disarm ownership before attempting close so Drop cannot close a
        // subsequently reused descriptor number. Both mapping guards remain
        // live through this last fallible construction operation.
        let fd = core::mem::replace(&mut self.fd, -1);
        // SAFETY: fd is live; both mappings retain their backing object.
        if unsafe { libc::close(fd) } != 0 {
            return Err(os_error("close trampoline arena memfd"));
        }
        let arena = TrampolineArena {
            writable: self.writable.cast(),
            executable: self.executable.cast(),
            len: self.len,
            next: next.address,
            reservation_len: next.len,
        };
        self.writable = core::ptr::null_mut();
        self.executable = core::ptr::null_mut();
        core::mem::forget(next);
        Ok(arena)
    }

    fn publish_at(
        mut self,
        image: &TrampolineImage,
        entry_offset: usize,
    ) -> Result<ExecutableTrampoline, TrampolineError> {
        let initialized_end =
            entry_offset
                .checked_add(image.bytes.len())
                .ok_or(TrampolineError::CodeTooLarge {
                    code_len: image.bytes.len(),
                    allocation_len: self.len,
                })?;
        if initialized_end > self.len {
            return Err(TrampolineError::CodeTooLarge {
                code_len: initialized_end,
                allocation_len: self.len,
            });
        }
        // SAFETY: the writable alias contains the complete destination range.
        unsafe {
            core::ptr::copy_nonoverlapping(
                image.bytes.as_ptr(),
                self.writable.cast::<u8>().add(entry_offset),
                image.bytes.len(),
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: writable is the live mapping returned by mmap.
        if unsafe { libc::munmap(self.writable, self.len) } != 0 {
            return Err(os_error("munmap writable alias"));
        }
        self.writable = core::ptr::null_mut();
        // Linux may release the descriptor even when close reports an error.
        // Disarm it first so failure cleanup cannot close a reused descriptor.
        let fd = core::mem::replace(&mut self.fd, -1);
        // SAFETY: fd is live; mappings retain their backing object.
        if unsafe { libc::close(fd) } != 0 {
            return Err(os_error("close trampoline memfd"));
        }
        let mapping_address = self.executable as usize as u64;
        let address = mapping_address.checked_add(entry_offset as u64).ok_or(
            TrampolineError::AddressNotRepresentable {
                address: mapping_address,
            },
        )?;
        self.executable = core::ptr::null_mut();
        Ok(ExecutableTrampoline {
            address,
            mapping_address,
            allocation_len: self.len,
            code_len: image.bytes.len(),
            layout: image.layout,
            program_counters: image.program_counters.clone().into_boxed_slice(),
            controls: ManuallyDrop::new(image.controls.clone()),
            clock: ManuallyDrop::new(image.clock.clone()),
            program_counters_published: AtomicBool::new(false),
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
    let maps = read_process_maps_bounded()?;
    let record_count = maps.lines().count();
    let max_records = MAX_PROCESS_MAPS_BYTES / MIN_PROCESS_MAP_RECORD_BYTES + 1;
    if record_count > max_records {
        return Err(TrampolineError::ProcessMaps {
            message: format!(
                "/proc/self/maps contains {record_count} records; limit is {max_records}"
            ),
        });
    }
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(record_count)
        .map_err(|error| TrampolineError::ProcessMaps {
            message: format!("could not reserve bounded process-map ranges: {error}"),
        })?;
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
    candidates
        .try_reserve_exact(ranges.len().saturating_add(1))
        .map_err(|error| TrampolineError::ProcessMaps {
            message: format!("could not reserve bounded near-map candidates: {error}"),
        })?;
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
    order_near_candidates(&mut candidates, next_ip);
    candidates.dedup();
    Ok(candidates)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_process_maps_bounded() -> Result<String, TrampolineError> {
    read_process_maps_from_open_result(std::fs::File::open("/proc/self/maps"))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
enum ProcessMapsIoOperation {
    Open,
    Read,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn process_maps_io_error(
    operation: ProcessMapsIoOperation,
    error: std::io::Error,
) -> TrampolineError {
    let operation = match operation {
        ProcessMapsIoOperation::Open => "open",
        ProcessMapsIoOperation::Read => "read",
    };
    // Formatting an OS error can enter libc's localized message lookup. Keep
    // real errno values numeric, and never format a custom error's payload.
    let message = if let Some(errno) = error.raw_os_error() {
        format!("{operation} /proc/self/maps: errno {errno}")
    } else {
        format!("{operation} /proc/self/maps: {:?}", error.kind())
    };
    TrampolineError::ProcessMaps { message }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_process_maps_from_open_result<R: std::io::Read>(
    opened: std::io::Result<R>,
) -> Result<String, TrampolineError> {
    let reader =
        opened.map_err(|error| process_maps_io_error(ProcessMapsIoOperation::Open, error))?;
    read_process_maps_from(reader)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_process_maps_from(mut reader: impl std::io::Read) -> Result<String, TrampolineError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(MAX_PROCESS_MAPS_BYTES)
        .map_err(|error| TrampolineError::ProcessMaps {
            message: format!("could not reserve bounded process-map bytes: {error}"),
        })?;
    let mut chunk = [0_u8; 4096];
    loop {
        let amount = reader
            .read(&mut chunk)
            .map_err(|error| process_maps_io_error(ProcessMapsIoOperation::Read, error))?;
        if amount == 0 {
            break;
        }
        let Some(new_length) = bytes.len().checked_add(amount) else {
            return Err(TrampolineError::ProcessMaps {
                message: "/proc/self/maps byte length overflowed".to_owned(),
            });
        };
        if new_length > MAX_PROCESS_MAPS_BYTES {
            return Err(TrampolineError::ProcessMaps {
                message: format!("/proc/self/maps exceeds its {MAX_PROCESS_MAPS_BYTES}-byte limit"),
            });
        }
        bytes.extend_from_slice(&chunk[..amount]);
    }
    String::from_utf8(bytes).map_err(|error| TrampolineError::ProcessMaps {
        message: format!("/proc/self/maps is not UTF-8: {error}"),
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn order_near_candidates(candidates: &mut [usize], next_ip: usize) {
    // A mapping above the program image can begin exactly where [heap] ends,
    // permanently capping future brk growth. Lower gaps cannot obstruct the
    // upward-growing heap, and every candidate is already within rel32 reach.
    candidates.sort_unstable_by_key(|candidate| {
        let is_above = *candidate > next_ip;
        (is_above, candidate.abs_diff(next_ip))
    });
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

// These two ownership tests must not compete with unrelated unit tests for
// near-map gaps or for the address between a tested drop and exact reclamation.
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
fn run_staged_drop_test(name: &str, body: fn()) {
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const CHILD: &str = "LITEINST2_STAGED_DROP_CHILD";
    const BODY_RETURNED: i32 = 102;
    assert!(matches!(
        name,
        "trampoline::tests::dropping_staged_image_releases_its_exact_mapping"
            | "trampoline::observing_control_tests::observing_control_staged_drop_unmaps_before_releasing_last_owners"
    ));
    if let Some(selected) = std::env::var_os(CHILD) {
        assert_eq!(selected.as_os_str(), std::ffi::OsStr::new(name));
        body();
        // SAFETY: the complete body has returned, including all local drops.
        // This distinct receipt cannot be produced by an empty test filter.
        unsafe { libc::_exit(BODY_RETURNED) };
    }

    struct ReapOnUnwind(Option<Child>);
    impl Drop for ReapOnUnwind {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                // A parent failure must not leave a test child running. The
                // ordinary success path disarms this only after try_wait reaps.
                let killed = child.kill();
                let reaped = child.wait();
                if killed.is_err() || reaped.is_err() {
                    eprintln!("staged-drop child cleanup: kill={killed:?}, reap={reaped:?}");
                }
            }
        }
    }

    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    // Exact exit status below authenticates complete body and local-drop execution.
    // Suppress unfinished child libtest progress; --nocapture keeps assertion
    // diagnostics on inherited stderr.
    // SAFETY: only async-signal-safe resource calls run before child exec.
    unsafe {
        command.pre_exec(|| {
            for (resource, value) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_CPU, 5)] {
                let limit = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = ReapOnUnwind(Some(command.spawn().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.0.as_mut().unwrap().try_wait() {
            Ok(Some(status)) => {
                drop(child.0.take()); // try_wait already reaped this child.
                break status;
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => panic!("{name}: child exceeded ten seconds"),
            Err(error) => panic!("{name}: could not poll child: {error}"),
        }
    };
    assert_eq!(
        status.code(),
        Some(BODY_RETURNED),
        "{name}: complete child body did not return: {status}"
    );
}

#[cfg(test)]
mod tests {
    use super::HookContext;
    use super::SavedExtendedStateLayout;
    use super::TrampolineError;
    use super::TrampolineLayout;
    use super::TrampolinePlan;
    use super::encode_return_jump;
    use crate::scanner::InstructionScanner;

    unsafe extern "C" fn noop_hook(_context: *mut HookContext) {}

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod process_maps_io_regressions {
        use super::super::read_process_maps_from;
        use super::super::read_process_maps_from_open_result;
        use super::TrampolineError;
        use std::fmt;
        use std::io;
        use std::io::Read;
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;

        fn process_maps_message(error: TrampolineError) -> String {
            match error {
                TrampolineError::ProcessMaps { message } => message,
                _ => panic!("maps IO failure changed its ProcessMaps classification"),
            }
        }

        struct ErrorReader {
            error: Option<io::Error>,
            reads: Arc<AtomicUsize>,
        }

        impl Read for ErrorReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                self.reads.fetch_add(1, Ordering::Relaxed);
                Err(self.error.take().expect("maps reader retried its error"))
            }
        }

        struct CountingPayload {
            displays: Arc<AtomicUsize>,
            debugs: Arc<AtomicUsize>,
        }

        impl fmt::Display for CountingPayload {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.displays.fetch_add(1, Ordering::Relaxed);
                formatter.write_str("maps payload Display must not be consulted")
            }
        }

        impl fmt::Debug for CountingPayload {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.debugs.fetch_add(1, Ordering::Relaxed);
                formatter.write_str("maps payload Debug must not be consulted")
            }
        }

        impl std::error::Error for CountingPayload {}

        #[test]
        fn open_result_reports_numeric_errno_without_reading() {
            static READS: AtomicUsize = AtomicUsize::new(0);
            struct MustNotRead;

            impl Read for MustNotRead {
                fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                    READS.fetch_add(1, Ordering::Relaxed);
                    panic!("an open error reached the maps reader");
                }
            }

            READS.store(0, Ordering::Relaxed);
            let error = read_process_maps_from_open_result::<MustNotRead>(Err(
                io::Error::from_raw_os_error(libc::EMFILE),
            ))
            .unwrap_err();
            let message = process_maps_message(error);
            assert_eq!(READS.load(Ordering::Relaxed), 0);
            assert_eq!(message, "open /proc/self/maps: errno 24");
        }

        #[test]
        fn read_error_reports_numeric_errno() {
            let reads = Arc::new(AtomicUsize::new(0));
            let error = read_process_maps_from(ErrorReader {
                error: Some(io::Error::from_raw_os_error(libc::EBADF)),
                reads: Arc::clone(&reads),
            })
            .unwrap_err();
            let message = process_maps_message(error);
            assert_eq!(reads.load(Ordering::Relaxed), 1);
            assert_eq!(message, "read /proc/self/maps: errno 9");
        }

        #[test]
        fn read_error_retains_kind_without_display_or_debug_of_its_payload() {
            let reads = Arc::new(AtomicUsize::new(0));
            let displays = Arc::new(AtomicUsize::new(0));
            let debugs = Arc::new(AtomicUsize::new(0));
            let error = io::Error::new(
                io::ErrorKind::PermissionDenied,
                CountingPayload {
                    displays: Arc::clone(&displays),
                    debugs: Arc::clone(&debugs),
                },
            );
            assert_eq!(error.raw_os_error(), None);
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            let error = read_process_maps_from(ErrorReader {
                error: Some(error),
                reads: Arc::clone(&reads),
            })
            .unwrap_err();
            let message = process_maps_message(error);
            assert_eq!(reads.load(Ordering::Relaxed), 1);
            assert_eq!(
                (
                    displays.load(Ordering::Relaxed),
                    debugs.load(Ordering::Relaxed),
                ),
                (0, 0),
            );
            assert_eq!(message, "read /proc/self/maps: PermissionDenied");
        }

        #[test]
        fn open_result_delegates_success_to_the_bounded_reader() {
            struct CountingReader {
                bytes: io::Cursor<&'static [u8]>,
                reads: Arc<AtomicUsize>,
            }

            impl Read for CountingReader {
                fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                    self.reads.fetch_add(1, Ordering::Relaxed);
                    self.bytes.read(buffer)
                }
            }

            let expected: &'static [u8] =
                b"00400000-00401000 r-xp 00000000 00:00 0 /maps-fixture\n";
            let reads = Arc::new(AtomicUsize::new(0));
            let actual = read_process_maps_from_open_result(Ok(CountingReader {
                bytes: io::Cursor::new(expected),
                reads: Arc::clone(&reads),
            }))
            .unwrap();
            assert_eq!(reads.load(Ordering::Relaxed), 2);
            assert_eq!(actual.as_bytes(), expected);
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn process_maps_reader_accepts_the_exact_cap_and_rejects_one_extra_byte() {
        let exact = vec![b'x'; super::MAX_PROCESS_MAPS_BYTES];
        assert_eq!(
            super::read_process_maps_from(std::io::Cursor::new(exact))
                .unwrap()
                .len(),
            super::MAX_PROCESS_MAPS_BYTES
        );
        let oversized = vec![b'x'; super::MAX_PROCESS_MAPS_BYTES + 1];
        assert!(matches!(
            super::read_process_maps_from(std::io::Cursor::new(oversized)),
            Err(TrampolineError::ProcessMaps { .. })
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn arena_seals_preserve_existing_writer_and_close_external_mutation_paths() {
        let name = b"liteinst2-seal-test\0";
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr().cast::<libc::c_char>(),
                libc::MFD_CLOEXEC | 0x0002,
            ) as libc::c_int
        };
        assert!(fd >= 0);
        let page = 4096_usize;
        assert_eq!(unsafe { libc::ftruncate(fd, page as libc::off_t) }, 0);
        let writable = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        let executable = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(writable, libc::MAP_FAILED);
        assert_ne!(executable, libc::MAP_FAILED);
        let held = unsafe { libc::dup(fd) };
        assert!(held >= 0);

        super::seal_arena_backing(fd).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(held, libc::F_GET_SEALS) },
            super::ARENA_REQUIRED_SEALS
        );
        unsafe { writable.cast::<u8>().write_volatile(0x5a) };
        assert_eq!(unsafe { executable.cast::<u8>().read_volatile() }, 0x5a);

        let byte = 0xa5_u8;
        assert_eq!(
            unsafe { libc::pwrite(held, (&raw const byte).cast(), 1, 0) },
            -1
        );
        assert_eq!(
            unsafe { libc::ftruncate(held, (2 * page) as libc::off_t) },
            -1
        );
        assert_eq!(
            unsafe { libc::ftruncate(held, (page / 2) as libc::off_t) },
            -1
        );
        let new_writer = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                held,
                0,
            )
        };
        assert_eq!(new_writer, libc::MAP_FAILED);

        assert_eq!(unsafe { libc::munmap(writable, page) }, 0);
        assert_eq!(unsafe { libc::munmap(executable, page) }, 0);
        assert_eq!(unsafe { libc::close(held) }, 0);
        assert_eq!(unsafe { libc::close(fd) }, 0);
    }

    #[test]
    fn exhausted_arena_reservation_cannot_wrap_and_reuse_storage() {
        use core::sync::atomic::AtomicUsize;
        use core::sync::atomic::Ordering;
        let near_wrap = usize::MAX - (super::TRAMPOLINE_ALLOCATION_BYTES - 1);
        let last_start = near_wrap - super::TRAMPOLINE_ALLOCATION_BYTES;
        let cursor = AtomicUsize::new(last_start);
        assert_eq!(
            super::reserve_arena_slot(&cursor, usize::MAX).unwrap(),
            last_start
        );
        assert_eq!(cursor.load(Ordering::Acquire), near_wrap);
        for _ in 0..32 {
            assert!(matches!(
                super::reserve_arena_slot(&cursor, usize::MAX),
                Err(TrampolineError::ArenaFull)
            ));
            assert_eq!(cursor.load(Ordering::Acquire), near_wrap);
        }
        let cursor = AtomicUsize::new(super::TRAMPOLINE_ALLOCATION_BYTES);
        assert!(matches!(
            super::reserve_arena_slot(&cursor, super::TRAMPOLINE_ALLOCATION_BYTES),
            Err(TrampolineError::ArenaFull)
        ));
        assert_eq!(
            cursor.load(Ordering::Acquire),
            super::TRAMPOLINE_ALLOCATION_BYTES
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn failed_emission_consumes_its_slot_without_overwriting_published_bytes() {
        let address = noop_hook as *const () as usize as u64;
        let scan = InstructionScanner::default()
            .scan(&[0xb8, 11, 0, 0, 0, 0xc3], address)
            .unwrap();
        let plan = TrampolinePlan::from_scan(&scan, address, noop_hook).unwrap();
        let arena = super::TrampolineArena::allocate_near(address, 3).unwrap();
        let first = arena.allocate(&plan).unwrap().address();
        let first_image = plan.emit_at(first).unwrap();
        // Public plan construction rejects malformed input. Construct an invalid
        // instruction here to exercise the real encoder error after reservation.
        let mut malformed = plan.clone();
        malformed.instructions[0] = iced_x86::Instruction::default();
        assert!(matches!(
            arena.allocate(&malformed),
            Err(TrampolineError::Encoding { .. })
        ));
        let third = arena.allocate(&plan).unwrap().address();
        assert_eq!(third - first, 2 * super::TRAMPOLINE_ALLOCATION_BYTES as u64);
        assert!(matches!(
            arena.allocate(&plan),
            Err(TrampolineError::ArenaFull)
        ));
        // SAFETY: these are process-lifetime RX mappings of three real slots.
        let retained =
            unsafe { core::slice::from_raw_parts(first as *const u8, first_image.bytes().len()) };
        assert_eq!(retained, first_image.bytes());
        let failed_slot = unsafe {
            core::slice::from_raw_parts(
                (first as usize + super::TRAMPOLINE_ALLOCATION_BYTES) as *const u8,
                super::TRAMPOLINE_ALLOCATION_BYTES,
            )
        };
        assert!(failed_slot.iter().all(|byte| *byte == 0));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn reachable_mapping_order_preserves_upward_heap_growth() {
        let next_ip = 0x401005;
        let below_image = 0x380000;
        let immediately_above_heap = 0x426000;
        let farther_below_image = 0x300000;
        let mut candidates = [immediately_above_heap, farther_below_image, below_image];

        super::order_near_candidates(&mut candidates, next_ip);

        assert_eq!(
            candidates,
            [below_image, farther_below_image, immediately_above_heap]
        );
    }

    fn plan(code: &[u8], base: u64) -> Result<TrampolinePlan, TrampolineError> {
        let scan = InstructionScanner::default()
            .scan(code, base)
            .expect("fixture must decode");
        TrampolinePlan::from_scan(&scan, base, noop_hook)
    }

    #[test]
    fn total_length_includes_every_section() {
        let layout = TrampolineLayout {
            relocated_prefix_len: 0,
            entry_stop_len: 1,
            instrumentation_len: 32,
            completion_stop_len: 1,
            relocated_len: 12,
            restore_len: 16,
            return_len: 5,
            saved_extended_state: SavedExtendedStateLayout::UNAVAILABLE,
        };
        assert_eq!(layout.total_len(), Some(67));
        assert_eq!(
            TrampolineLayout {
                relocated_prefix_len: 7,
                ..layout
            }
            .total_len(),
            Some(74)
        );
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
    fn relocates_multiple_short_instructions_as_one_patch_window() {
        let plan = plan(&[0x48, 0x89, 0xF8, 0x90, 0x90], 0x1000).unwrap();

        assert_eq!(plan.displaced_len(), 5);
        assert_eq!(plan.return_address(), 0x1005);
    }

    #[test]
    fn short_instruction_constructor_rejects_nonheads_and_long_instructions() {
        let base = 0x20_0000;
        // ADD RAX,1; MOV EAX,42; RET.
        let code = [0x48, 0x83, 0xc0, 1, 0xb8, 42, 0, 0, 0, 0xc3];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        for replace in [false, true] {
            for address in [base + 1, base + code.len() as u64] {
                assert!(matches!(
                    TrampolinePlan::from_short_instruction(&scan, address, noop_hook, replace),
                    Err(TrampolineError::SiteNotFound { .. })
                ));
            }
            assert!(matches!(
                TrampolinePlan::from_short_instruction(&scan, base + 4, noop_hook, replace),
                Err(TrampolineError::Encoding { .. })
            ));
            let short =
                TrampolinePlan::from_short_instruction(&scan, base, noop_hook, replace).unwrap();
            assert_eq!(short.instructions.len(), 1);
            assert_eq!(short.displaced_len(), 4);
            assert_eq!(short.return_address(), base + 4);
            assert!(matches!(
                TrampolinePlan::from_window(&scan, base, base, base + 4, noop_hook, replace),
                Err(TrampolineError::InstructionTooShort { .. })
            ));
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn short_instruction_emission_maps_exact_entry_and_original_end() {
        let base = 0x20_0000;
        let address = base + 0x10_0000;
        for code in [
            &[0x90][..],                // NOP
            &[0x01, 0xf8][..],          // ADD EAX,EDI
            &[0x48, 0x01, 0xf8][..],    // ADD RAX,RDI
            &[0x48, 0x83, 0xc0, 5][..], // ADD RAX,5
        ] {
            // A scan containing only this instruction is sufficient. No tail
            // bytes may be required to meet the separate near-jump encoding.
            let scan = InstructionScanner::default().scan(code, base).unwrap();
            for replace in [false, true] {
                let plan = TrampolinePlan::from_short_instruction(&scan, base, noop_hook, replace)
                    .unwrap();
                assert_eq!(plan.execute_address(), base);
                assert_eq!(plan.logical_address(), base);
                assert_eq!(plan.return_address(), base + code.len() as u64);
                assert_eq!(plan.displaced_len(), code.len());
                assert_eq!(plan.replaces_first(), replace);
                let image = plan.emit_at(address).unwrap();
                let layout = image.layout();
                assert_eq!(layout.relocated_prefix_len, 0);
                assert_eq!(layout.entry_stop_len, 0);
                assert_eq!(layout.completion_stop_len, 0);
                assert_eq!(layout.total_len(), Some(image.bytes().len()));
                assert_eq!(image.entry_routes(), &[(base, address)]);
                let relocated = address + (layout.instrumentation_len + layout.restore_len) as u64;
                if replace {
                    assert_eq!(layout.relocated_len, 0);
                    assert!(image.instruction_boundaries().is_empty());
                } else {
                    assert_eq!(image.instruction_boundaries(), &[(base, relocated)]);
                    let offset = (relocated - address) as usize;
                    let mut decoder = iced_x86::Decoder::with_ip(
                        64,
                        &image.bytes()[offset..offset + layout.relocated_len],
                        relocated,
                        iced_x86::DecoderOptions::NONE,
                    );
                    let instruction = decoder.decode();
                    assert_eq!(
                        instruction.code(),
                        scan.instructions()[0].instruction().code()
                    );
                    assert!(!decoder.can_decode(), "copied a successor instruction");
                }
                let return_offset = image.bytes().len() - layout.return_len;
                let return_pc = address + return_offset as u64;
                let mut decoder = iced_x86::Decoder::with_ip(
                    64,
                    &image.bytes()[return_offset..],
                    return_pc,
                    iced_x86::DecoderOptions::NONE,
                );
                assert_eq!(decoder.decode().near_branch_target(), plan.return_address());
                assert_eq!(
                    image
                        .program_counter_mappings()
                        .iter()
                        .find_map(|mapping| mapping.translate(return_pc)),
                    Some(plan.return_address())
                );
            }
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn short_instruction_native_observe_and_replace_resume_at_original_successor() {
        use core::sync::atomic::{AtomicU64, Ordering};

        static CALLBACKS: AtomicU64 = AtomicU64::new(0);
        static OBSERVED_PC: AtomicU64 = AtomicU64::new(0);
        static OBSERVED_RAX: AtomicU64 = AtomicU64::new(0);

        unsafe extern "C" fn observe(context: *mut HookContext) {
            // SAFETY: the trampoline supplies its initialized callback frame.
            let context = unsafe { &*context };
            OBSERVED_PC.store(context.instruction_pointer, Ordering::Relaxed);
            OBSERVED_RAX.store(context.rax, Ordering::Relaxed);
            CALLBACKS.fetch_add(1, Ordering::Relaxed);
        }

        unsafe extern "C" fn replace(context: *mut HookContext) {
            // SAFETY: the frame is exclusively borrowed for this callback. This
            // replacement deliberately implements RAX=100 instead of the ADD.
            unsafe {
                observe(context);
                (*context).rax = 100;
            }
        }

        struct Source(*mut u8, usize);
        impl Drop for Source {
            fn drop(&mut self) {
                // SAFETY: every fixture invocation has returned before drop.
                assert_eq!(unsafe { libc::munmap(self.0.cast(), self.1) }, 0);
            }
        }

        for (instruction, delta) in [
            (&[0x90][..], 0),
            (&[0x01, 0xf8][..], 3),
            (&[0x48, 0x01, 0xf8][..], 3),
            (&[0x48, 0x83, 0xc0, 5][..], 5),
        ] {
            let mut code = instruction.to_vec();
            code.extend_from_slice(&[0x48, 0x83, 0xc0, 64, 0xc3]); // ADD RAX,64; RET.
            let len = super::page_size().unwrap();
            // SAFETY: the test owns this private source page and publishes RX
            // only after initialization; it is never writable and executable.
            let source = unsafe {
                let mapping = libc::mmap(
                    core::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                assert_ne!(mapping, libc::MAP_FAILED);
                let source = Source(mapping.cast(), len);
                core::ptr::copy_nonoverlapping(code.as_ptr(), source.0, code.len());
                assert_eq!(
                    libc::mprotect(mapping, len, libc::PROT_READ | libc::PROT_EXEC),
                    0
                );
                source
            };
            let base = source.0 as usize as u64;
            let scan = InstructionScanner::default().scan(&code, base).unwrap();
            for replacing in [false, true] {
                let hook: super::HookCallback = if replacing { replace } else { observe };
                let plan =
                    TrampolinePlan::from_short_instruction(&scan, base, hook, replacing).unwrap();
                let trampoline = super::ExecutableTrampoline::allocate(&plan).unwrap();
                let before = CALLBACKS.load(Ordering::Relaxed);
                let result: u64;
                // SAFETY: the generated entry and original successor contain
                // qualified straight-line integer code and RET. Seed both ADD
                // operands, respecting the callback's System V ABI.
                unsafe {
                    core::arch::asm!(
                        "call r11",
                        in("r11") trampoline.address(),
                        in("rdi") 3_u64,
                        inlateout("rax") 10_u64 => result,
                        clobber_abi("C"),
                    );
                }
                assert_eq!(result, if replacing { 100 + 64 } else { 10 + delta + 64 });
                assert_eq!(CALLBACKS.load(Ordering::Relaxed), before + 1);
                assert_eq!(OBSERVED_PC.load(Ordering::Relaxed), base);
                assert_eq!(OBSERVED_RAX.load(Ordering::Relaxed), 10);
                assert_eq!(plan.return_address(), base + instruction.len() as u64);
                assert_eq!(
                    unsafe { core::slice::from_raw_parts(source.0, code.len()) },
                    code
                );
                // No global PC metadata or in-flight execution retains it.
                trampoline.discard();
            }
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod a2_emitter_foundation {
        use super::{HookContext, InstructionScanner, TrampolinePlan, noop_hook};
        use crate::trampoline::{ExecutableTrampoline, HookCallback};
        use core::sync::atomic::{AtomicU64, Ordering};

        static CALLS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
        static PCS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
        static VALUES: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
        static FLAGS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
        static STACKS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
        static ORDER: AtomicU64 = AtomicU64::new(0);

        unsafe fn record(context: *mut HookContext, index: usize) {
            // SAFETY: called only with the generated, initialized callback frame.
            let context = unsafe { &*context };
            CALLS[index].fetch_add(1, Ordering::Relaxed);
            PCS[index].store(context.instruction_pointer, Ordering::Relaxed);
            VALUES[index].store(context.rax, Ordering::Relaxed);
            FLAGS[index].store(context.rflags, Ordering::Relaxed);
            STACKS[index].store(context.stack_pointer, Ordering::Relaxed);
            ORDER.store(
                ORDER.load(Ordering::Relaxed) * 3 + index as u64 + 1,
                Ordering::Relaxed,
            );
        }

        unsafe extern "C" fn first(context: *mut HookContext) {
            unsafe { record(context, 0) };
        }
        unsafe extern "C" fn second(context: *mut HookContext) {
            unsafe { record(context, 1) };
        }
        unsafe extern "C" fn replace_first(context: *mut HookContext) {
            unsafe {
                record(context, 0);
                (*context).rax = 100;
            }
        }
        unsafe extern "C" fn replace_second(context: *mut HookContext) {
            unsafe {
                record(context, 1);
                (*context).rax = 1000;
            }
        }
        fn reset() {
            for value in CALLS
                .iter()
                .chain(PCS.iter())
                .chain(VALUES.iter())
                .chain(FLAGS.iter())
                .chain(STACKS.iter())
                .chain([&ORDER])
            {
                value.store(0, Ordering::Relaxed);
            }
        }

        struct Source(*mut u8, usize);
        impl Source {
            fn new(bytes: &[u8]) -> Self {
                let len = crate::trampoline::page_size().unwrap();
                assert!(bytes.len() <= len);
                // SAFETY: privately owned initialized RW storage becomes RX
                // before any entry executes. There is never an RWX mapping.
                unsafe {
                    let mapping = libc::mmap(
                        core::ptr::null_mut(),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    );
                    assert_ne!(mapping, libc::MAP_FAILED);
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapping.cast(), bytes.len());
                    assert_eq!(
                        libc::mprotect(mapping, len, libc::PROT_READ | libc::PROT_EXEC),
                        0
                    );
                    Self(mapping.cast(), len)
                }
            }
            fn address(&self) -> u64 {
                self.0 as usize as u64
            }
        }
        impl Drop for Source {
            fn drop(&mut self) {
                // SAFETY: all fixture entries and trampolines have drained.
                assert_eq!(unsafe { libc::munmap(self.0.cast(), self.1) }, 0);
            }
        }
        unsafe fn invoke(entry: u64, value: u64, count: u64) -> (u64, u64, u64) {
            let result;
            let remaining;
            let flags;
            // SAFETY: callers supply finite System V fixtures, initialized
            // operands and an authenticated emitted entry. CLC seeds CF.
            unsafe {
                core::arch::asm!(
                    "clc", "call r11", "pushfq", "pop rdx",
                    in("r11") entry,
                    inlateout("rax") value => result,
                    inlateout("rcx") count => remaining,
                    lateout("rdx") flags,
                    clobber_abi("C"),
                );
            }
            (result, remaining, flags)
        }

        #[test]
        fn validates_exact_instruction_and_ordered_action_boundaries() {
            let base = 0x20_0000;
            let code = [0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xc0, 2, 0xc3];
            let scan = InstructionScanner::default().scan(&code, base).unwrap();
            assert!(TrampolinePlan::from_instruction(&scan, base + 1).is_err());
            assert!(TrampolinePlan::from_instruction(&scan, base + 9).is_err());
            for actions in [
                vec![],
                vec![(base + 1, noop_hook as HookCallback, false)],
                vec![(base, noop_hook, false), (base, noop_hook, true)],
                vec![(base + 4, noop_hook, false), (base, noop_hook, false)],
                vec![(base, noop_hook, false), (base + 9, noop_hook, false)],
            ] {
                assert!(TrampolinePlan::from_actions(&scan, base, base + 9, &actions).is_err());
            }
            assert!(
                TrampolinePlan::from_actions(&scan, base, base + 7, &[(base, noop_hook, false)])
                    .is_err()
            );
            assert!(
                TrampolinePlan::from_actions(&scan, base, base + 4, &[(base, noop_hook, false)])
                    .is_err()
            );
            for replace in [false, true] {
                let legacy = TrampolinePlan::from_window(
                    &scan,
                    base,
                    base + 4,
                    base + 9,
                    noop_hook,
                    replace,
                )
                .unwrap()
                .emit_at(base + 0x10_0000)
                .unwrap();
                let actions = TrampolinePlan::from_actions(
                    &scan,
                    base,
                    base + 9,
                    &[(base + 4, noop_hook, replace)],
                )
                .unwrap()
                .emit_at(base + 0x10_0000)
                .unwrap();
                assert_eq!(actions, legacy, "straight-line single-action legacy parity");
            }
        }

        #[test]
        fn callback_free_lengths_and_far_branch_maps_are_exact() {
            let base = 0x20_0000;
            for len in 1..=15 {
                let mut code = vec![0x66; len - 1];
                code.push(0x90);
                let scan = InstructionScanner::default().scan(&code, base).unwrap();
                let plan = TrampolinePlan::from_instruction(&scan, base).unwrap();
                assert_eq!(plan.displaced_len(), len);
                assert_eq!(plan.return_address(), base + len as u64);
                assert!(!plan.replaces_first());
                let image = plan.emit_at(base + 0x10_0000).unwrap();
                assert_eq!(image.layout().instrumentation_len, 0);
                assert_eq!(image.layout().restore_len, 0);
                assert_eq!(image.layout().total_len(), Some(image.bytes().len()));
                assert_eq!(image.entry_routes(), &[(base, image.address())]);
                assert_eq!(image.instruction_boundaries(), image.entry_routes());
                let return_offset = image.bytes().len() - image.layout().return_len;
                let mut decoder = iced_x86::Decoder::with_ip(
                    64,
                    &image.bytes()[return_offset..],
                    image.address() + return_offset as u64,
                    iced_x86::DecoderOptions::NONE,
                );
                assert_eq!(decoder.decode().near_branch_target(), base + len as u64);
            }
            let scan = InstructionScanner::default()
                .scan(&[0x74, 0x7f], base)
                .unwrap();
            let image = TrampolinePlan::from_instruction(&scan, base)
                .unwrap()
                .emit_at(0x80_0000_0000)
                .unwrap();
            let relay = image
                .program_counter_mappings()
                .iter()
                .find(|mapping| mapping.logical_address() == base + 129)
                .unwrap();
            let offset = (relay.generated_start() - image.address()) as usize;
            assert_eq!(
                &image.bytes()[offset..offset + crate::trampoline::BRANCH_RELAY_CODE.len()],
                &crate::trampoline::BRANCH_RELAY_CODE
            );
            assert!(
                image
                    .program_counter_mappings()
                    .iter()
                    .all(|mapping| mapping.translate(relay.generated_end()).is_none()),
                "absolute relay target is data, not executable PC metadata"
            );
        }

        fn native_cases() {
            // Every supported architectural instruction length resumes at its
            // original end; duplicate operand-size prefixes form one NOP.
            for len in 1..=15 {
                let mut code = vec![0x66; len - 1];
                code.extend_from_slice(&[0x90, 0xb8, 123, 0, 0, 0, 0xc3]);
                let source = Source::new(&code);
                let scan = InstructionScanner::default()
                    .scan(&code, source.address())
                    .unwrap();
                let plan = TrampolinePlan::from_instruction(&scan, source.address()).unwrap();
                let trampoline = ExecutableTrampoline::allocate(&plan).unwrap();
                assert_eq!(unsafe { invoke(trampoline.address(), 10, 3) }.0, 123);
                assert_eq!(plan.return_address(), source.address() + len as u64);
                trampoline.discard();
            }

            // Every original head is entered independently. The second hook
            // must see the first instruction's restored result and fresh flags.
            let code = [
                0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xc0, 2, 0x48, 0x83, 0xc0, 4, 0xc3,
            ];
            let source = Source::new(&code);
            let base = source.address();
            let scan = InstructionScanner::default().scan(&code, base).unwrap();
            for replacing_first in [false, true] {
                for replacing_second in [false, true] {
                    let hook0: HookCallback = if replacing_first {
                        replace_first
                    } else {
                        first
                    };
                    let hook1: HookCallback = if replacing_second {
                        replace_second
                    } else {
                        second
                    };
                    let plan = TrampolinePlan::from_actions(
                        &scan,
                        base,
                        base + code.len() as u64,
                        &[
                            (base + 4, hook0, replacing_first),
                            (base + 8, hook1, replacing_second),
                        ],
                    )
                    .unwrap();
                    let trampoline = ExecutableTrampoline::allocate(&plan).unwrap();
                    let image = plan.emit_at(trampoline.address()).unwrap();
                    assert_eq!(image.entry_routes().len(), 4);
                    assert_eq!(
                        image.instruction_boundaries().len(),
                        4 - usize::from(replacing_first) - usize::from(replacing_second)
                    );
                    for &(pc, generated) in image.instruction_boundaries() {
                        assert_eq!(
                            image
                                .program_counter_mappings()
                                .iter()
                                .find_map(|mapping| mapping.translate(generated)),
                            Some(pc)
                        );
                    }
                    for initial in [10_u64, u64::MAX] {
                        for (entry, &(_, generated)) in image.entry_routes().iter().enumerate() {
                            reset();
                            let (mut expected, mut carry) = if entry == 0 {
                                initial.overflowing_add(1)
                            } else {
                                (initial, false)
                            };
                            let first_value = expected;
                            let first_carry = carry;
                            if entry <= 1 {
                                if replacing_first {
                                    expected = 100;
                                } else {
                                    (expected, carry) = expected.overflowing_add(2);
                                }
                            }
                            let second_value = expected;
                            let second_carry = carry;
                            if entry <= 2 {
                                if replacing_second {
                                    expected = 1000;
                                } else {
                                    expected = expected.wrapping_add(4);
                                }
                            }
                            assert_eq!(unsafe { invoke(generated, initial, 3) }.0, expected);
                            assert_eq!(CALLS[0].load(Ordering::Relaxed), u64::from(entry <= 1));
                            assert_eq!(CALLS[1].load(Ordering::Relaxed), u64::from(entry <= 2));
                            assert_eq!(
                                ORDER.load(Ordering::Relaxed),
                                if entry <= 1 {
                                    5
                                } else if entry == 2 {
                                    2
                                } else {
                                    0
                                }
                            );
                            if entry <= 1 {
                                assert_eq!(PCS[0].load(Ordering::Relaxed), base + 4);
                                assert_eq!(VALUES[0].load(Ordering::Relaxed), first_value);
                                assert_eq!(
                                    FLAGS[0].load(Ordering::Relaxed) & 1,
                                    u64::from(first_carry)
                                );
                                assert_eq!(
                                    STACKS[0].load(Ordering::Relaxed),
                                    STACKS[1].load(Ordering::Relaxed)
                                );
                            }
                            if entry <= 2 {
                                assert_eq!(PCS[1].load(Ordering::Relaxed), base + 8);
                                assert_eq!(VALUES[1].load(Ordering::Relaxed), second_value);
                                assert_eq!(
                                    FLAGS[1].load(Ordering::Relaxed) & 1,
                                    u64::from(second_carry)
                                );
                            }
                        }
                    }
                    trampoline.discard();
                }
            }

            // A coalesced window ending before the original continuation must
            // resume there from each entry, with only the remaining callbacks.
            let code = [
                0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xc0, 2, 0x48, 0x83, 0xc0, 4, 0x48, 0x83, 0xc0, 8,
                0xc3,
            ];
            let source = Source::new(&code);
            let base = source.address();
            let scan = InstructionScanner::default().scan(&code, base).unwrap();
            let plan = TrampolinePlan::from_actions(
                &scan,
                base,
                base + 12,
                &[(base + 4, first, false), (base + 8, second, false)],
            )
            .unwrap();
            let trampoline = ExecutableTrampoline::allocate(&plan).unwrap();
            let image = plan.emit_at(trampoline.address()).unwrap();
            let return_pc =
                image.address() + (image.bytes().len() - image.layout().return_len) as u64;
            assert_eq!(
                image
                    .program_counter_mappings()
                    .iter()
                    .find_map(|mapping| mapping.translate(return_pc)),
                Some(base + 12)
            );
            for (index, (&(_, entry), expected)) in
                image.entry_routes().iter().zip([25, 24, 22]).enumerate()
            {
                reset();
                assert_eq!(unsafe { invoke(entry, 10, 3) }.0, expected);
                assert_eq!(CALLS[0].load(Ordering::Relaxed), u64::from(index < 2));
                assert_eq!(CALLS[1].load(Ordering::Relaxed), 1);
            }
            trampoline.discard();

            // A forward branch to the second action bypasses only the first.
            let code = [0xeb, 4, 0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xc0, 2, 0xc3];
            let source = Source::new(&code);
            let base = source.address();
            let scan = InstructionScanner::default().scan(&code, base).unwrap();
            let plan = TrampolinePlan::from_actions(
                &scan,
                base,
                base + code.len() as u64,
                &[(base + 2, first, false), (base + 6, second, false)],
            )
            .unwrap();
            let trampoline = ExecutableTrampoline::allocate(&plan).unwrap();
            reset();
            assert_eq!(unsafe { invoke(trampoline.address(), 10, 3) }.0, 12);
            assert_eq!(CALLS[0].load(Ordering::Relaxed), 0);
            assert_eq!(CALLS[1].load(Ordering::Relaxed), 1);
            trampoline.discard();

            // LOOP self must decrement the restored RCX and visit its logical
            // hook on each iteration. No source patch is needed for this test:
            // taking a branch to original code would miss the required hooks.
            let code = [0xe2, 0xfe, 0x48, 0x89, 0xc8, 0xc3];
            let source = Source::new(&code);
            let base = source.address();
            let scan = InstructionScanner::default().scan(&code, base).unwrap();
            let plan = TrampolinePlan::from_instruction(&scan, base).unwrap();
            let trampoline = ExecutableTrampoline::allocate(&plan).unwrap();
            let (value, remaining, flags) = unsafe { invoke(trampoline.address(), 7, 3) };
            assert_eq!((value, remaining, flags & 1), (0, 0, 0));
            trampoline.discard();
            let plan = TrampolinePlan::from_actions(
                &scan,
                base,
                base + code.len() as u64,
                &[(base, first, false), (base + 2, second, false)],
            )
            .unwrap();
            let trampoline = ExecutableTrampoline::allocate(&plan).unwrap();
            reset();
            assert_eq!(unsafe { invoke(trampoline.address(), 7, 3) }.0, 0);
            assert_eq!(CALLS[0].load(Ordering::Relaxed), 3);
            assert_eq!(CALLS[1].load(Ordering::Relaxed), 1);
            assert_eq!(PCS[0].load(Ordering::Relaxed), base);
            assert_eq!(PCS[1].load(Ordering::Relaxed), base + 2);
            trampoline.discard();

            // Force branch expansion and the encoder's literal pool. Both the
            // taken relay and the fallthrough terminal must reach *original*
            // application addresses, never synthetic encoder identities.
            let code = [0xe3, 6, 0xb8, 11, 0, 0, 0, 0xc3, 0xb8, 22, 0, 0, 0, 0xc3];
            let source = Source::new(&code);
            let base = source.address();
            let scan = InstructionScanner::default().scan(&code, base).unwrap();
            let plan = TrampolinePlan::from_instruction(&scan, base).unwrap();
            let mapping =
                crate::trampoline::PendingMapping::allocate_near(base ^ (1 << 34)).unwrap();
            let address = mapping.executable as usize as u64;
            assert!(i128::from(address).abs_diff(i128::from(base)) > i32::MAX as u128);
            let image = plan.emit_at(address).unwrap();
            assert!(
                image
                    .program_counter_mappings()
                    .iter()
                    .any(|mapping| mapping.logical_address() == base + 8)
            );
            let trampoline = mapping.publish_at(&image, 0).unwrap();
            for (count, expected) in [(0, 22), (1, 11)] {
                let (value, remaining, flags) = unsafe { invoke(trampoline.address(), 7, count) };
                assert_eq!((value, remaining, flags & 1), (expected, count, 0));
            }
            trampoline.discard();

            // A cross-head conditional backedge observes freshly updated flags.
            let code = [0x48, 0xff, 0xc9, 0x75, 0xfb, 0x48, 0x89, 0xc8, 0xc3];
            let source = Source::new(&code);
            let base = source.address();
            let scan = InstructionScanner::default().scan(&code, base).unwrap();
            let plan = TrampolinePlan::from_actions(
                &scan,
                base,
                base + code.len() as u64,
                &[(base, first, false), (base + 3, second, false)],
            )
            .unwrap();
            let trampoline = ExecutableTrampoline::allocate(&plan).unwrap();
            reset();
            assert_eq!(unsafe { invoke(trampoline.address(), 7, 3) }.0, 0);
            assert_eq!(CALLS[0].load(Ordering::Relaxed), 3);
            assert_eq!(CALLS[1].load(Ordering::Relaxed), 3);
            trampoline.discard();

            // A branch to a replaced head runs the replacement on every visit,
            // rather than entering a removed instruction or bypassing its hook.
            let code = [0x48, 0x83, 0xc0, 1, 0x48, 0xff, 0xc9, 0x75, 0xf7, 0xc3];
            let source = Source::new(&code);
            let base = source.address();
            let scan = InstructionScanner::default().scan(&code, base).unwrap();
            let plan = TrampolinePlan::from_actions(
                &scan,
                base,
                base + code.len() as u64,
                &[(base, replace_first, true), (base + 4, second, false)],
            )
            .unwrap();
            let trampoline = ExecutableTrampoline::allocate(&plan).unwrap();
            reset();
            assert_eq!(unsafe { invoke(trampoline.address(), 7, 3) }.0, 100);
            assert_eq!(CALLS[0].load(Ordering::Relaxed), 3);
            assert_eq!(CALLS[1].load(Ordering::Relaxed), 3);
            assert_eq!(VALUES[1].load(Ordering::Relaxed), 100);
            trampoline.discard();

            // RIP-relative data equal to an instruction head remains an
            // application-address read even when that head has a callback.
            let code = [
                0x0f, 0xb6, 0x05, 0xf9, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc0, 1, 0xc3,
            ];
            let source = Source::new(&code);
            let base = source.address();
            let scan = InstructionScanner::default().scan(&code, base).unwrap();
            for plan in [
                TrampolinePlan::from_instruction(&scan, base).unwrap(),
                TrampolinePlan::from_actions(
                    &scan,
                    base,
                    base + code.len() as u64,
                    &[(base, first, false), (base + 7, second, false)],
                )
                .unwrap(),
            ] {
                let trampoline = ExecutableTrampoline::allocate(&plan).unwrap();
                reset();
                assert_eq!(unsafe { invoke(trampoline.address(), 7, 3) }.0, 0x10);
                trampoline.discard();
            }
            assert_eq!(
                unsafe { core::slice::from_raw_parts(source.0, code.len()) },
                code
            );
        }

        #[test]
        fn native_instructions_actions_and_backedges() {
            const CHILD: &str = "LI2_A2_EMITTER_CHILD";
            if std::env::var_os(CHILD).is_some() {
                native_cases();
                return;
            }
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "trampoline::tests::a2_emitter_foundation::native_instructions_actions_and_backedges",
                    "--nocapture", "--test-threads=1"])
                .env(CHILD, "1").spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "native emitter child failed: {status}");
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("native emitter child exceeded its 20-second bound");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn window_emission_separates_entry_routes_from_architectural_boundaries() {
        let base = 0x20_0000;
        let address = base + 0x10_0000;
        // ADD RAX,1; ADD RAX,2; ADD RAX,4; RET.
        let code = [
            0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xc0, 2, 0x48, 0x83, 0xc0, 4, 0xc3,
        ];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        let logical = base + 4;
        for replace in [false, true] {
            let plan = TrampolinePlan::from_window(
                &scan,
                base,
                logical,
                base + code.len() as u64,
                noop_hook,
                replace,
            )
            .unwrap();
            let image = plan.emit_at(address).unwrap();
            let layout = image.layout();
            assert_eq!(image.address(), address);
            assert_eq!(plan.execute_address(), base);
            assert_eq!(plan.logical_address(), logical);
            assert_eq!(plan.return_address(), base + code.len() as u64);
            assert_eq!(layout.relocated_prefix_len, 4);
            assert_eq!(layout.total_len(), Some(image.bytes().len()));
            assert_eq!(&image.bytes()[..4], &code[..4]);
            assert_eq!(
                image
                    .entry_routes()
                    .iter()
                    .map(|&(pc, _)| pc)
                    .collect::<Vec<_>>(),
                [base, logical, base + 8, base + 12]
            );
            assert_eq!(image.entry_routes()[0], (base, address));
            assert_eq!(image.entry_routes()[1], (logical, address + 4));
            let restored = address
                + layout.relocated_prefix_len as u64
                + layout.instrumentation_len as u64
                + layout.restore_len as u64;
            let expected_boundaries = if replace {
                vec![
                    (base, address),
                    (base + 8, restored),
                    (base + 12, restored + 4),
                ]
            } else {
                vec![
                    (base, address),
                    (logical, restored),
                    (base + 8, restored + 4),
                    (base + 12, restored + 8),
                ]
            };
            assert_eq!(image.instruction_boundaries(), expected_boundaries);
            for &(original, generated) in image.instruction_boundaries() {
                assert_eq!(
                    image
                        .program_counter_mappings()
                        .iter()
                        .find_map(|mapping| { mapping.translate(generated) }),
                    Some(original)
                );
            }
            let instrumentation = &image.bytes()[layout.relocated_prefix_len
                ..layout.relocated_prefix_len + layout.instrumentation_len];
            let mut decoder = iced_x86::Decoder::with_ip(
                64,
                instrumentation,
                address + 4,
                iced_x86::DecoderOptions::NONE,
            );
            assert!(decoder.iter().any(|instruction| {
                instruction.mnemonic() == iced_x86::Mnemonic::Mov
                    && instruction.op0_register() == iced_x86::Register::RAX
                    && instruction.op1_kind() == iced_x86::OpKind::Immediate64
                    && instruction.immediate64() == logical
            }));
        }
    }

    #[test]
    fn window_constructor_requires_complete_physical_logical_and_end_boundaries() {
        let base = 0x20_0000;
        let code = [0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xc0, 2, 0xc3];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        for (physical, logical, end) in [
            (base + 1, base + 4, base + 9),
            (base, base + 1, base + 9),
            (base, base + 4, base + 7),
            (base, base + 4, base + 10),
            (base, base + 9, base + 9),
            (base + 4, base, base + 9),
            (base, base, base + 4),
        ] {
            assert!(
                TrampolinePlan::from_window(&scan, physical, logical, end, noop_hook, false)
                    .is_err(),
                "accepted physical={physical:#x}, logical={logical:#x}, end={end:#x}"
            );
        }
        assert!(
            TrampolinePlan::from_window(&scan, base, base + 4, base + 9, noop_hook, false).is_ok()
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn same_site_window_emits_identical_legacy_bytes_and_layout() {
        let base = 0x20_0000;
        let code = [0x48, 0x89, 0xf8, 0x90, 0x90, 0xc3];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        for replace in [false, true] {
            let legacy = if replace {
                TrampolinePlan::from_scan_replacing_first(&scan, base, noop_hook)
            } else {
                TrampolinePlan::from_scan(&scan, base, noop_hook)
            }
            .unwrap();
            let window = TrampolinePlan::from_window(
                &scan,
                base,
                base,
                legacy.return_address(),
                noop_hook,
                replace,
            )
            .unwrap();
            let legacy = legacy.emit_at(base + 0x10_0000).unwrap();
            let window = window.emit_at(base + 0x10_0000).unwrap();
            assert_eq!(legacy, window);
            assert_eq!(legacy.layout().relocated_prefix_len, 0);
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn staged_image_rejects_wrong_address_without_mapping() {
        let base = 0x20_0000;
        let plan = plan(&[0x90; 5], base).unwrap();
        let image = plan.emit_at(base + 0x10_0000).unwrap();
        assert!(matches!(
            super::ExecutableTrampoline::allocate_image_at(&image, image.address() + 1),
            Err(TrampolineError::Encoding { .. })
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn upstream_entries_execute_the_required_prefix_hook_and_suffix() {
        use core::sync::atomic::{AtomicU64, Ordering};

        static CALLBACKS: AtomicU64 = AtomicU64::new(0);
        static OBSERVED_PC: AtomicU64 = AtomicU64::new(0);
        static OBSERVED_RDI: AtomicU64 = AtomicU64::new(0);

        unsafe extern "C" fn observe(context: *mut HookContext) {
            // SAFETY: the emitted trampoline provides its live callback frame.
            let context = unsafe { &*context };
            OBSERVED_PC.store(context.instruction_pointer, Ordering::Relaxed);
            OBSERVED_RDI.store(context.rdi, Ordering::Relaxed);
            CALLBACKS.fetch_add(1, Ordering::Relaxed);
        }

        let base = observe as *const () as usize as u64;
        // ADD RDI,1; ADD RDI,2; LEA RAX,[RDI+4]; RET.
        let code = [
            0x48, 0x83, 0xc7, 1, 0x48, 0x83, 0xc7, 2, 0x48, 0x8d, 0x47, 4, 0xc3,
        ];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        for replace in [false, true] {
            let plan = TrampolinePlan::from_window(
                &scan,
                base,
                base + 4,
                base + code.len() as u64,
                observe,
                replace,
            )
            .unwrap();
            let trampoline = super::ExecutableTrampoline::allocate(&plan).unwrap();
            let image = plan.emit_at(trampoline.address()).unwrap();
            let initial_calls = CALLBACKS.load(Ordering::Relaxed);
            for (index, &(original, generated)) in image.entry_routes().iter().enumerate() {
                let result: u64;
                // SAFETY: each entry has straight-line integer operations and
                // RET, follows the System V ABI, and has no external targets.
                // Seed RAX too so the bare RET entry has a defined result.
                unsafe {
                    core::arch::asm!(
                        "call r11",
                        in("r11") generated,
                        in("rdi") 10_u64,
                        inlateout("rax") 10_u64 => result,
                        clobber_abi("C"),
                    );
                }
                let expected_result = if index < 3 {
                    let prefix = u64::from(index == 0);
                    let logical = if index < 2 && !replace { 2 } else { 0 };
                    10 + prefix + logical + 4
                } else {
                    10
                };
                assert_eq!(result, expected_result);
                let expected_calls = initial_calls + (index as u64 + 1).min(2);
                assert_eq!(CALLBACKS.load(Ordering::Relaxed), expected_calls);
                if original <= base + 4 {
                    assert_eq!(OBSERVED_PC.load(Ordering::Relaxed), base + 4);
                    assert_eq!(
                        OBSERVED_RDI.load(Ordering::Relaxed),
                        10 + u64::from(index == 0)
                    );
                }
            }
            assert_eq!(
                trampoline.relocated_tail_address(),
                image.instruction_boundaries()[1].1
            );
            // No global metadata or in-flight execution retains this mapping.
            trampoline.discard();
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn dropping_staged_image_releases_its_exact_mapping() {
        super::run_staged_drop_test(
            "trampoline::tests::dropping_staged_image_releases_its_exact_mapping",
            dropping_staged_image_releases_its_exact_mapping_body,
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn dropping_staged_image_releases_its_exact_mapping_body() {
        let base = noop_hook as *const () as usize as u64;
        let plan = plan(&[0x90, 0x90, 0x90, 0x90, 0xc3], base).unwrap();
        let mapping = super::PendingMapping::allocate_near(base).unwrap();
        let address = mapping.executable as usize as u64;
        let image = plan.emit_at(address).unwrap();
        assert!(matches!(
            super::ExecutableTrampoline::allocate_image_at(&image, address),
            Err(TrampolineError::ExactAddressUnavailable { .. })
        ));
        // Transfer the already reserved mapping directly into a pending guard,
        // avoiding any free-address race before the tested drop.
        let staged = super::PendingExecutableTrampoline {
            trampoline: Some(mapping.publish_at(&image, 0).unwrap()),
        };
        assert_eq!(staged.trampoline().address(), address);
        drop(staged);
        // Exact MAP_FIXED_NOREPLACE succeeds only if Drop released the page.
        let staged = super::ExecutableTrampoline::allocate_image_at(&image, address).unwrap();
        assert_eq!(staged.trampoline().code_len(), image.bytes().len());
        let committed = staged.commit();
        assert_eq!(committed.address(), address);
        committed.discard();
    }

    #[test]
    fn rejects_a_short_region_without_five_complete_bytes() {
        let error = plan(&[0x48, 0x89, 0xF8], 0x1000).unwrap_err();

        assert!(matches!(
            error,
            TrampolineError::InstructionTooShort {
                address: 0x1000,
                instruction_len: 3
            }
        ));
    }

    #[test]
    fn out_of_range_return_uses_cet_notrack_indirect_jump() {
        let target = 0x1_0000_0000;
        let jump = encode_return_jump(0, target).unwrap();

        assert_eq!(&jump[..7], &[0x3E, 0xFF, 0x25, 0, 0, 0, 0]);
        assert_eq!(&jump[7..], &target.to_le_bytes());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn replace_first_omits_a_two_byte_syscall_but_relocates_its_tail() {
        let base = 0x20_0000;
        let code = [0x0F, 0x05, 0x48, 0x83, 0xC0, 0x01];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        let plan = TrampolinePlan::from_scan_replacing_first(&scan, base, noop_hook).unwrap();
        let image = plan.emit_at(base + 0x10_0000).unwrap();

        assert!(plan.replaces_first());
        assert_eq!(plan.displaced_len(), 6);
        assert_eq!(plan.return_address(), base + 6);
        assert!(image.layout().relocated_len > 0);
        assert_eq!(image.layout().entry_stop_len, 0);
        assert_eq!(image.layout().completion_stop_len, 0);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn ptrace_stops_restore_saved_state_but_leave_rsp_at_owned_top() {
        let base = 0x20_0000;
        let trampoline = base + 0x10_0000;
        let code = [0x0F, 0x05, 0x48, 0x83, 0xC0, 0x01];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        let plan =
            TrampolinePlan::from_scan_replacing_first_with_ptrace_stops(&scan, base, noop_hook)
                .unwrap();
        let image = plan.emit_at(trampoline).unwrap();
        let layout = image.layout();
        let completion_offset =
            layout.entry_stop_len + layout.instrumentation_len + layout.restore_len;
        let relocated_offset = completion_offset + layout.completion_stop_len;

        assert_eq!(layout.entry_stop_len, 1);
        assert_eq!(layout.completion_stop_len, 1);
        assert_eq!(image.bytes()[0], 0xcc);
        assert_eq!(image.bytes()[completion_offset], 0xcc);
        let instrumentation_start = layout.entry_stop_len;
        let instrumentation_end = instrumentation_start + layout.instrumentation_len;
        let mut decoder = iced_x86::Decoder::with_ip(
            64,
            &image.bytes()[instrumentation_start..instrumentation_end],
            trampoline + instrumentation_start as u64,
            iced_x86::DecoderOptions::NONE,
        );
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            instructions.push(decoder.decode());
        }
        assert!(instructions.iter().any(|instruction| {
            instruction.mnemonic() == iced_x86::Mnemonic::Mov
                && instruction.op0_register() == iced_x86::Register::RAX
                && instruction.op1_kind() == iced_x86::OpKind::Memory
                && instruction.memory_base() == iced_x86::Register::RSP
                && instruction.memory_displacement64() == 280
        }));
        assert!(!instructions.iter().any(|instruction| {
            instruction.mnemonic() == iced_x86::Mnemonic::Lea
                && instruction.op0_register() == iced_x86::Register::RAX
                && instruction.memory_base() == iced_x86::Register::RSP
                && instruction.memory_displacement64() == 288
        }));
        let restore_start = instrumentation_end;
        let restore_end = restore_start + layout.restore_len;
        let mut restore_decoder = iced_x86::Decoder::with_ip(
            64,
            &image.bytes()[restore_start..restore_end],
            trampoline + restore_start as u64,
            iced_x86::DecoderOptions::NONE,
        );
        let mut restore_instructions = Vec::new();
        while restore_decoder.can_decode() {
            restore_instructions.push(restore_decoder.decode());
        }
        assert!(restore_instructions.iter().any(|instruction| {
            instruction.mnemonic() == iced_x86::Mnemonic::Mov
                && instruction.op0_register() == iced_x86::Register::RSP
                && instruction.op1_register() == iced_x86::Register::R12
        }));
        let final_restore = restore_instructions.last().unwrap();
        assert_eq!(final_restore.mnemonic(), iced_x86::Mnemonic::Lea);
        assert_eq!(final_restore.op0_register(), iced_x86::Register::RSP);
        assert_eq!(final_restore.memory_base(), iced_x86::Register::RSP);
        assert_eq!(final_restore.memory_displacement64(), 128);
        let owned_top = 0x7100_0000_u64;
        let context_base = owned_top - super::HOOK_CONTEXT_STACK_PREFIX_BYTES as u64;
        assert_eq!(
            context_base + super::HOOK_CONTEXT_STACK_PREFIX_BYTES as u64,
            owned_top
        );
        assert_ne!(owned_top, 0x7fff_0000_u64, "RSP is not yet application RSP");
        let executable = super::ExecutableTrampoline {
            address: trampoline,
            allocation_len: super::TRAMPOLINE_ALLOCATION_BYTES,
            mapping_address: 0,
            code_len: image.bytes().len(),
            layout,
            program_counters: Box::new([]),
            controls: core::mem::ManuallyDrop::new(Vec::new()),
            clock: core::mem::ManuallyDrop::new(None),
            program_counters_published: std::sync::atomic::AtomicBool::new(false),
        };
        assert_eq!(executable.ptrace_entry_stop_rip(), Some(trampoline + 1));
        assert_eq!(
            executable.ptrace_completion_stop_rip(),
            Some(trampoline + relocated_offset as u64)
        );
        assert_eq!(
            executable.relocated_tail_address(),
            trampoline + relocated_offset as u64
        );
        assert_eq!(
            image
                .program_counter_mappings()
                .iter()
                .find_map(|mapping| mapping.translate(trampoline)),
            Some(base)
        );
        assert_eq!(
            image
                .program_counter_mappings()
                .iter()
                .find_map(|mapping| mapping.translate(trampoline + relocated_offset as u64)),
            Some(base + 2)
        );
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
            assert_eq!(image.layout().return_len, 5);
            let return_offset = image.bytes().len() - image.layout().return_len;
            let return_address = base + 0x10_0000 + return_offset as u64;
            let jump = &image.bytes()[return_offset..];
            assert_eq!(jump[0], 0xE9);
            let displacement = i32::from_le_bytes(jump[1..].try_into().unwrap());
            assert_eq!(
                i128::from(return_address + 5) + i128::from(displacement),
                i128::from(plan.return_address())
            );

            let relocated_address = base
                + 0x10_0000
                + image.layout().instrumentation_len as u64
                + image.layout().restore_len as u64;
            assert_eq!(
                image
                    .program_counter_mappings()
                    .iter()
                    .find_map(|mapping| mapping.translate(relocated_address)),
                Some(base)
            );
            assert_eq!(
                image
                    .program_counter_mappings()
                    .iter()
                    .find_map(|mapping| mapping.translate(return_address)),
                Some(plan.return_address())
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod pc_relative {
        use super::{InstructionScanner, TrampolineError, TrampolinePlan, noop_hook};
        use crate::trampoline::{BRANCH_RELAY_BYTES, BRANCH_RELAY_CODE, TrampolineImage};
        use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};

        fn memory_code(opcode: &[u8], eip: bool, ip: u64, target: u64) -> Vec<u8> {
            let mut code = Vec::new();
            if eip {
                code.push(0x67);
            }
            code.extend_from_slice(opcode);
            let next_ip = ip + code.len() as u64 + 4;
            let displacement = if eip {
                u32::try_from(target).unwrap().wrapping_sub(next_ip as u32)
            } else {
                i32::try_from(target as i128 - next_ip as i128).unwrap() as u32
            };
            code.extend_from_slice(&displacement.to_le_bytes());
            let decoded = Decoder::with_ip(64, &code, ip, DecoderOptions::NONE).decode();
            assert!(!decoded.is_invalid());
            assert_eq!(decoded.ip_rel_memory_address(), target);
            code
        }

        fn make_plan(code: &[u8], base: u64, replace_first: bool) -> TrampolinePlan {
            let scan = InstructionScanner::default().scan(code, base).unwrap();
            if replace_first {
                TrampolinePlan::from_scan_replacing_first(&scan, base, noop_hook).unwrap()
            } else {
                TrampolinePlan::from_scan(&scan, base, noop_hook).unwrap()
            }
        }

        fn relocated(image: &TrampolineImage, address: u64) -> Decoder<'_> {
            let layout = image.layout();
            let start = layout.instrumentation_len + layout.restore_len;
            Decoder::with_ip(
                64,
                &image.bytes()[start..start + layout.relocated_len],
                address + start as u64,
                DecoderOptions::NONE,
            )
        }

        fn logical_pc(image: &TrampolineImage, address: u64) -> Option<u64> {
            image
                .program_counter_mappings()
                .iter()
                .find_map(|mapping| mapping.translate(address))
        }

        fn assert_branch_relay(image: &TrampolineImage, address: u64, relay: u64, target: u64) {
            let offset = usize::try_from(relay - address).unwrap();
            let mut decoder =
                Decoder::with_ip(64, &image.bytes()[offset..], relay, DecoderOptions::NONE);
            let endbr = decoder.decode();
            assert_eq!(endbr.code(), Code::Endbr64);
            let jump = decoder.decode();
            assert_eq!(jump.code(), Code::Jmp_rm64);
            assert_eq!(jump.segment_prefix(), iced_x86::Register::DS);
            assert_eq!(jump.ip_rel_memory_address(), jump.next_ip());
            let literal = usize::try_from(jump.next_ip() - address).unwrap();
            assert_eq!(
                u64::from_le_bytes(image.bytes()[literal..literal + 8].try_into().unwrap()),
                target
            );
            for pc in relay..jump.next_ip() {
                assert_eq!(logical_pc(image, pc), Some(target));
            }
            for pc in jump.next_ip()..jump.next_ip() + 8 {
                assert_eq!(logical_pc(image, pc), None);
            }
        }

        fn make_mode_plan(
            code: &[u8],
            base: u64,
            replace_first: bool,
            stops: bool,
        ) -> TrampolinePlan {
            let scan = InstructionScanner::default().scan(code, base).unwrap();
            if stops {
                assert!(replace_first);
                TrampolinePlan::from_scan_replacing_first_with_ptrace_stops(&scan, base, noop_hook)
                    .unwrap()
            } else if replace_first {
                TrampolinePlan::from_scan_replacing_first(&scan, base, noop_hook).unwrap()
            } else {
                TrampolinePlan::from_scan(&scan, base, noop_hook).unwrap()
            }
        }

        fn relocated_bounds(image: &TrampolineImage, address: u64) -> (usize, u64, u64) {
            let layout = image.layout();
            let offset = layout.entry_stop_len
                + layout.instrumentation_len
                + layout.restore_len
                + layout.completion_stop_len;
            let start = address + offset as u64;
            (offset, start, start + layout.relocated_len as u64)
        }

        fn relay_for_transfer(
            image: &TrampolineImage,
            address: u64,
            transfer: &Instruction,
            target: u64,
        ) -> u64 {
            assert_eq!(transfer.op0_kind(), OpKind::Memory);
            let pool = transfer.ip_rel_memory_address();
            let pool_offset = usize::try_from(pool - address).unwrap();
            let relay = u64::from_le_bytes(
                image.bytes()[pool_offset..pool_offset + 8]
                    .try_into()
                    .unwrap(),
            );
            assert_branch_relay(image, address, relay, target);
            for pc in pool..pool + 8 {
                assert_eq!(logical_pc(image, pc), None);
            }
            relay
        }

        fn decode_terminal(decoder: &mut Decoder<'_>) -> Instruction {
            loop {
                let instruction = decoder.decode();
                if instruction.mnemonic() != Mnemonic::Nop {
                    return instruction;
                }
            }
        }

        fn assert_memory(original: &Instruction, emitted: &Instruction) {
            assert!(!emitted.is_invalid());
            assert_eq!(
                emitted.ip_rel_memory_address(),
                original.ip_rel_memory_address()
            );
            assert_eq!(emitted.code(), original.code());
            assert_eq!(emitted.op_count(), original.op_count());
            for operand in 0..original.op_count() {
                assert_eq!(emitted.op_kind(operand), original.op_kind(operand));
                if original.op_kind(operand) == OpKind::Register {
                    assert_eq!(emitted.op_register(operand), original.op_register(operand));
                }
            }
            assert_eq!(emitted.memory_size(), original.memory_size());
            assert_eq!(emitted.segment_prefix(), original.segment_prefix());
        }

        #[test]
        fn preserves_memory_targets_for_all_operand_classes() {
            let mut cases = 0;
            for opcode in [
                &[0x48, 0x8d, 0x05][..],
                &[0x48, 0x8b, 0x05],
                &[0x48, 0x89, 0x05],
                &[0xff, 0x15],
                &[0xff, 0x25],
            ] {
                for eip in [false, true] {
                    for base in [0, 0x20_0000] {
                        for preceding_nop in [false, true] {
                            let memory_ip = base + u64::from(preceding_nop);
                            for target in [memory_ip, base, base + 2, base + 0x100, 0] {
                                let mut code = if preceding_nop { vec![0x90] } else { vec![] };
                                code.extend(memory_code(opcode, eip, memory_ip, target));
                                let plan = make_plan(&code, base, false);
                                let original = plan.instructions.clone();
                                for destination in [base + 0x10_0000, 0x4_0000_0000] {
                                    let image = plan.emit_at(destination).unwrap();
                                    let emitted =
                                        relocated(&image, destination).into_iter().last().unwrap();
                                    assert_memory(original.last().unwrap(), &emitted);
                                    for pc in emitted.ip()..emitted.next_ip() {
                                        assert_eq!(logical_pc(&image, pc), Some(memory_ip));
                                    }
                                    assert_eq!(plan.instructions, original);
                                    cases += 1;
                                }
                            }
                        }
                    }
                }
            }
            assert_eq!(cases, 400);
        }

        #[test]
        fn preserves_eip_wrap_and_high_ip_external_targets() {
            for base in [0xffff_fffc, 0x1_0000_1000] {
                for target in [base as u32 as u64, 0, 2] {
                    let code = memory_code(&[0x48, 0x8d, 0x05], true, base, target);
                    let plan = make_plan(&code, base, false);
                    for destination in [base + 0x10_0000, 0x8_0000_0000] {
                        let image = plan.emit_at(destination).unwrap();
                        assert_memory(
                            &plan.instructions[0],
                            &relocated(&image, destination).decode(),
                        );
                    }
                }
            }
        }

        #[test]
        fn keeps_entry_branches_and_memory_at_application_address() {
            for base in [0, 1, 0x20_0000] {
                for eip in [false, true] {
                    // Both operands name the hook entry. The branch must revisit
                    // the live patch; the memory address must remain original.
                    let mut code = vec![0x75, 0xfe];
                    code.extend(memory_code(&[0x48, 0x8d, 0x05], eip, base + 2, base));
                    let plan = make_plan(&code, base, false);
                    let original = plan.instructions.clone();
                    for destination in [base + 0x10_0000, 0x4_0000_0000] {
                        let image = plan.emit_at(destination).unwrap();
                        let mut decoder = relocated(&image, destination);
                        let branch = decoder.decode();
                        if destination < 0x4_0000_0000 {
                            assert_eq!(branch.mnemonic(), Mnemonic::Jne);
                            assert_eq!(branch.near_branch_target(), base);
                        } else {
                            assert_eq!(branch.mnemonic(), Mnemonic::Je);
                            let transfer = decoder.decode();
                            assert_eq!(transfer.mnemonic(), Mnemonic::Jmp);
                            assert_eq!(transfer.op0_kind(), OpKind::Memory);
                            let offset = (transfer.ip_rel_memory_address() - destination) as usize;
                            let relay = u64::from_le_bytes(
                                image.bytes()[offset..offset + 8].try_into().unwrap(),
                            );
                            assert_branch_relay(&image, destination, relay, base);
                            assert_eq!(branch.near_branch_target(), decoder.ip());
                            assert_eq!(logical_pc(&image, transfer.ip()), Some(base));
                        }
                        let memory = decoder.decode();
                        assert_memory(&original[1], &memory);
                        assert_eq!(logical_pc(&image, memory.ip()), Some(base + 2));
                        assert_eq!(logical_pc(&image, branch.ip()), Some(base));
                        assert_eq!(plan.instructions, original);
                    }
                }
            }
        }

        #[test]
        fn retained_interior_branches_still_follow_their_relocated_instruction() {
            for base in [0, 1, 0x20_0000] {
                for eip in [false, true] {
                    // This is an encoder-only control. Installed hooks still
                    // reject strict-interior entries. The NOP is the hook entry;
                    // the retained branch and LEA both address the branch itself.
                    let mut code = vec![0x90, 0x75, 0xfe];
                    code.extend(memory_code(&[0x48, 0x8d, 0x05], eip, base + 3, base + 1));
                    for replace_first in [false, true] {
                        let plan = make_plan(&code, base, replace_first);
                        let original = plan.instructions.clone();
                        for destination in [base + 0x10_0000, 0x4_0000_0000] {
                            let image = plan.emit_at(destination).unwrap();
                            let mut decoder = relocated(&image, destination);
                            if !replace_first {
                                assert_eq!(decoder.decode().mnemonic(), Mnemonic::Nop);
                            }
                            let branch = decoder.decode();
                            assert_eq!(branch.near_branch_target(), branch.ip());
                            assert_memory(&original[2], &decoder.decode());
                            assert_eq!(logical_pc(&image, branch.ip()), Some(base + 1));
                            assert_eq!(plan.instructions, original);
                        }
                    }
                }
            }
        }

        #[test]
        fn observing_entry_targets_stay_external_for_direct_control_flow() {
            for code in [
                &[0xeb, 0xfe, 0x90, 0x90, 0x90][..],   // JMP rel8
                &[0xe9, 0xfb, 0xff, 0xff, 0xff],       // JMP rel32
                &[0x75, 0xfe, 0x90, 0x90, 0x90],       // JNE rel8
                &[0x0f, 0x85, 0xfa, 0xff, 0xff, 0xff], // JNE rel32
                &[0xe8, 0xfb, 0xff, 0xff, 0xff],       // CALL rel32
                &[0xe2, 0xfe, 0x90, 0x90, 0x90],       // LOOP
                &[0xe1, 0xfe, 0x90, 0x90, 0x90],       // LOOPE
                &[0xe0, 0xfe, 0x90, 0x90, 0x90],       // LOOPNE
                &[0xe3, 0xfe, 0x90, 0x90, 0x90],       // JRCXZ
                &[0x67, 0xe3, 0xfd, 0x90, 0x90],       // JECXZ
            ] {
                for base in [0, 1, 0x20_0000] {
                    let plan = make_plan(code, base, false);
                    let original = plan.instructions.clone();
                    let destination = base + 0x10_0000;
                    let image = plan.emit_at(destination).unwrap();
                    let instructions: Vec<_> = relocated(&image, destination).into_iter().collect();
                    let targets: Vec<_> = instructions
                        .iter()
                        .filter(|instruction| instruction.op0_kind() == OpKind::NearBranch64)
                        .map(Instruction::near_branch_target)
                        .collect();
                    assert!(
                        targets.contains(&base),
                        "code={code:02x?}; targets={targets:x?}"
                    );
                    assert!(!targets.contains(&instructions[0].ip()));
                    assert_eq!(plan.instructions, original);
                }
            }
        }

        #[test]
        fn maps_consecutive_far_entry_backedges_to_their_original_pcs() {
            let base = 0x20_0000;
            let plan = make_plan(&[0x75, 0xfe, 0x74, 0xfc, 0x90], base, false);
            let destination = 0x4_0000_0000;
            let image = plan.emit_at(destination).unwrap();
            let mut decoder = relocated(&image, destination);
            let mut common_relay = None;
            for original_pc in [base, base + 2] {
                let conditional = decoder.decode();
                let transfer = decoder.decode();
                assert!(matches!(
                    conditional.mnemonic(),
                    Mnemonic::Je | Mnemonic::Jne
                ));
                assert_eq!(conditional.near_branch_target(), transfer.next_ip());
                assert_eq!(transfer.mnemonic(), Mnemonic::Jmp);
                assert_eq!(transfer.op0_kind(), OpKind::Memory);
                let offset = (transfer.ip_rel_memory_address() - destination) as usize;
                let relay =
                    u64::from_le_bytes(image.bytes()[offset..offset + 8].try_into().unwrap());
                assert_branch_relay(&image, destination, relay, base);
                if let Some(previous) = common_relay {
                    assert_eq!(relay, previous);
                }
                common_relay = Some(relay);
                for pc in conditional.ip()..transfer.next_ip() {
                    assert_eq!(logical_pc(&image, pc), Some(original_pc));
                }
            }
            let nop = decoder.decode();
            assert_eq!(nop.mnemonic(), Mnemonic::Nop);
            assert_eq!(logical_pc(&image, nop.ip()), Some(base + 4));
            let terminal = decoder.decode();
            assert_eq!(terminal.code(), Code::Jmp_rel32_64);
            for pc in terminal.ip()..terminal.next_ip() {
                assert_eq!(logical_pc(&image, pc), Some(plan.return_address()));
            }
            let return_stub = destination
                + (image.layout().instrumentation_len
                    + image.layout().restore_len
                    + image.layout().relocated_len) as u64;
            assert_eq!(terminal.near_branch_target(), return_stub);
            let relay = common_relay.unwrap();
            assert_eq!(relay + 19, return_stub);
            for pc in terminal.next_ip()..relay {
                assert_eq!(logical_pc(&image, pc), None);
            }
        }

        #[test]
        fn far_entry_relay_preserves_all_direct_transfer_kinds_and_fallthrough() {
            for code in [
                &[0xe9, 0xfb, 0xff, 0xff, 0xff][..], // JMP
                &[0xe8, 0xfb, 0xff, 0xff, 0xff],     // CALL
                &[0x75, 0xfe, 0x90, 0x90, 0x90],     // JNE
                &[0xe2, 0xfe, 0x90, 0x90, 0x90],     // LOOP
                &[0xe1, 0xfe, 0x90, 0x90, 0x90],     // LOOPE
                &[0xe0, 0xfe, 0x90, 0x90, 0x90],     // LOOPNE
                &[0xe3, 0xfe, 0x90, 0x90, 0x90],     // JRCXZ
                &[0x67, 0xe3, 0xfd, 0x90, 0x90],     // JECXZ
            ] {
                // The first placement is a forward rel32-limit patch target;
                // the displaced backedge is nevertheless too far to return.
                for (base, destination) in [(0x200ffc, 0x80201000), (0x20_0000, 0x4_0000_0000)] {
                    if base == 0x200ffc {
                        assert_eq!(destination - (base + 5), i32::MAX as u64);
                        assert_eq!(destination % 4096, 0);
                        let mut patch_code = code.to_vec();
                        patch_code.resize(8, 0x90);
                        let scanner = InstructionScanner::default();
                        let scan = scanner.scan(&patch_code, base).unwrap();
                        crate::patcher::JumpPatchPlan::from_scan(
                            &scanner,
                            &scan,
                            &patch_code,
                            base,
                            base,
                            destination,
                        )
                        .unwrap();
                    }
                    let plan = make_plan(code, base, false);
                    let image = plan.emit_at(destination).unwrap();
                    let mut decoder = relocated(&image, destination);
                    let start = decoder.ip();
                    let mut transfers = Vec::new();
                    let indirect = loop {
                        let instruction = decoder.decode();
                        assert!(!instruction.is_invalid());
                        transfers.push(instruction);
                        if matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
                            && instruction.op0_kind() == OpKind::Memory
                        {
                            break instruction;
                        }
                    };
                    assert_eq!(
                        indirect.mnemonic(),
                        if code[0] == 0xe8 {
                            Mnemonic::Call
                        } else {
                            Mnemonic::Jmp
                        }
                    );
                    let literal = (indirect.ip_rel_memory_address() - destination) as usize;
                    let relay =
                        u64::from_le_bytes(image.bytes()[literal..literal + 8].try_into().unwrap());
                    assert_branch_relay(&image, destination, relay, base);
                    for pc in start..indirect.next_ip() {
                        assert_eq!(logical_pc(&image, pc), Some(base));
                    }
                    // Inverted Jcc fallthrough and LOOP's skip land immediately
                    // after the indirect transfer. CALL returns there as well.
                    if code[0] == 0x75 {
                        assert_eq!(transfers[0].near_branch_target(), indirect.next_ip());
                    } else if matches!(code[0], 0xe0..=0xe3 | 0x67) {
                        assert_eq!(transfers[0].near_branch_target(), indirect.ip());
                        assert_eq!(transfers[1].near_branch_target(), indirect.next_ip());
                    }
                    let terminal = loop {
                        let instruction = decoder.decode();
                        if instruction.mnemonic() != Mnemonic::Nop {
                            break instruction;
                        }
                    };
                    assert_eq!(terminal.code(), Code::Jmp_rel32_64);
                    let return_stub = destination
                        + (image.layout().instrumentation_len
                            + image.layout().restore_len
                            + image.layout().relocated_len) as u64;
                    assert_eq!(terminal.near_branch_target(), return_stub);
                    assert_eq!(relay + 19, return_stub);
                    for pc in terminal.next_ip()..relay {
                        assert_eq!(logical_pc(&image, pc), None);
                    }
                }
            }
        }

        #[test]
        fn far_external_direct_branch_uses_cet_relay() {
            let code = [0x75, 0x40, 0x90, 0x90, 0x90];
            for (base, destination) in [(0x200ffc, 0x80201000), (0x20_0000, 0x4_0000_0000)] {
                if base == 0x200ffc {
                    assert_eq!(destination - (base + 5), i32::MAX as u64);
                    assert_eq!(destination % 4096, 0);
                    let mut patch_code = code.to_vec();
                    patch_code.resize(8, 0x90);
                    let scanner = InstructionScanner::default();
                    let scan = scanner.scan(&patch_code, base).unwrap();
                    crate::patcher::JumpPatchPlan::from_scan(
                        &scanner,
                        &scan,
                        &patch_code,
                        base,
                        base,
                        destination,
                    )
                    .unwrap();
                }

                let target = base + 0x42;
                let plan = make_plan(&code, base, false);
                let image = plan.emit_at(destination).unwrap();
                let layout = image.layout();
                let relocated_offset = layout.instrumentation_len + layout.restore_len;
                let relocated_address = destination + relocated_offset as u64;
                let return_stub = relocated_address + layout.relocated_len as u64;
                let mut decoder = relocated(&image, destination);

                let conditional = decoder.decode();
                assert_eq!(conditional.mnemonic(), Mnemonic::Je);
                let transfer = decoder.decode();
                assert_eq!(transfer.code(), Code::Jmp_rm64);
                assert_eq!(conditional.near_branch_target(), transfer.next_ip());
                for pc in conditional.ip()..transfer.next_ip() {
                    assert_eq!(logical_pc(&image, pc), Some(base));
                }

                let pool_address = transfer.ip_rel_memory_address();
                let pool_offset = usize::try_from(pool_address - destination).unwrap();
                let relay = u64::from_le_bytes(
                    image.bytes()[pool_offset..pool_offset + 8]
                        .try_into()
                        .unwrap(),
                );
                assert!(
                    relay >= relocated_address && relay.checked_add(19).unwrap() <= return_stub,
                    "external branch pool must point to an in-image relay: {relay:#x}"
                );
                for pc in pool_address..pool_address + 8 {
                    assert_eq!(logical_pc(&image, pc), None);
                }

                let relay_offset = usize::try_from(relay - destination).unwrap();
                let mut relay_decoder = Decoder::with_ip(
                    64,
                    &image.bytes()[relay_offset..return_stub as usize - destination as usize],
                    relay,
                    DecoderOptions::NONE,
                );
                let endbr = relay_decoder.decode();
                assert_eq!(endbr.code(), Code::Endbr64);
                let jump = relay_decoder.decode();
                assert_eq!(jump.code(), Code::Jmp_rm64);
                assert_eq!(jump.segment_prefix(), iced_x86::Register::DS);
                assert_eq!(jump.ip_rel_memory_address(), jump.next_ip());
                let target_offset = usize::try_from(jump.next_ip() - destination).unwrap();
                assert_eq!(
                    u64::from_le_bytes(
                        image.bytes()[target_offset..target_offset + 8]
                            .try_into()
                            .unwrap()
                    ),
                    target
                );
                for pc in relay..jump.next_ip() {
                    assert_eq!(logical_pc(&image, pc), Some(target));
                }
                for pc in jump.next_ip()..jump.next_ip() + 8 {
                    assert_eq!(logical_pc(&image, pc), None);
                }

                let terminal = loop {
                    let instruction = decoder.decode();
                    if instruction.mnemonic() != Mnemonic::Nop {
                        break instruction;
                    }
                };
                assert_eq!(terminal.code(), Code::Jmp_rel32_64);
                assert_eq!(terminal.near_branch_target(), return_stub);
                assert_eq!(relay + 19, return_stub);
            }
        }

        #[test]
        fn far_external_relays_cover_all_direct_forms_and_plan_modes() {
            struct Case {
                name: &'static str,
                observing: &'static [u8],
                replacing: &'static [u8],
            }
            let cases = [
                Case {
                    name: "jmp_rel8",
                    observing: &[0xeb, 0x40, 0x90, 0x90, 0x90],
                    replacing: &[0x90, 0xeb, 0x3f, 0x90, 0x90],
                },
                Case {
                    name: "jmp_rel32",
                    observing: &[0xe9, 0x3d, 0, 0, 0],
                    replacing: &[0x90, 0xe9, 0x3c, 0, 0, 0],
                },
                Case {
                    name: "call_rel32",
                    observing: &[0xe8, 0x3d, 0, 0, 0],
                    replacing: &[0x90, 0xe8, 0x3c, 0, 0, 0],
                },
                Case {
                    name: "jne_rel8",
                    observing: &[0x75, 0x40, 0x90, 0x90, 0x90],
                    replacing: &[0x90, 0x75, 0x3f, 0x90, 0x90],
                },
                Case {
                    name: "jne_rel32",
                    observing: &[0x0f, 0x85, 0x3c, 0, 0, 0],
                    replacing: &[0x90, 0x0f, 0x85, 0x3b, 0, 0, 0],
                },
                Case {
                    name: "loop",
                    observing: &[0xe2, 0x40, 0x90, 0x90, 0x90],
                    replacing: &[0x90, 0xe2, 0x3f, 0x90, 0x90],
                },
                Case {
                    name: "loope",
                    observing: &[0xe1, 0x40, 0x90, 0x90, 0x90],
                    replacing: &[0x90, 0xe1, 0x3f, 0x90, 0x90],
                },
                Case {
                    name: "loopne",
                    observing: &[0xe0, 0x40, 0x90, 0x90, 0x90],
                    replacing: &[0x90, 0xe0, 0x3f, 0x90, 0x90],
                },
                Case {
                    name: "jrcxz",
                    observing: &[0xe3, 0x40, 0x90, 0x90, 0x90],
                    replacing: &[0x90, 0xe3, 0x3f, 0x90, 0x90],
                },
                Case {
                    name: "jecxz",
                    observing: &[0x67, 0xe3, 0x3f, 0x90, 0x90],
                    replacing: &[0x90, 0x67, 0xe3, 0x3e, 0x90],
                },
            ];

            for case in cases {
                for (replace_first, stops) in [(false, false), (true, false), (true, true)] {
                    let code = if replace_first {
                        case.replacing
                    } else {
                        case.observing
                    };
                    for (base, destination) in [(0x200ffc, 0x80201000), (0x20_0000, 0x4_0000_0000)]
                    {
                        if base == 0x200ffc {
                            assert_eq!(destination - (base + 5), i32::MAX as u64);
                            let mut patch_code = code.to_vec();
                            patch_code.resize(8, 0x90);
                            let scanner = InstructionScanner::default();
                            let scan = scanner.scan(&patch_code, base).unwrap();
                            crate::patcher::JumpPatchPlan::from_scan(
                                &scanner,
                                &scan,
                                &patch_code,
                                base,
                                base,
                                destination,
                            )
                            .unwrap();
                        }

                        let plan = make_mode_plan(code, base, replace_first, stops);
                        assert_eq!(plan.replaces_first(), replace_first);
                        assert_eq!(plan.displaced_len(), code.len());
                        let image = plan.emit_at(destination).unwrap();
                        assert_eq!(image.layout().entry_stop_len, usize::from(stops));
                        assert_eq!(image.layout().completion_stop_len, usize::from(stops));
                        let (relocated_offset, relocated_address, return_stub) =
                            relocated_bounds(&image, destination);
                        let originals: Vec<_> =
                            Decoder::with_ip(64, code, base, DecoderOptions::NONE)
                                .into_iter()
                                .collect();
                        let original = originals[usize::from(replace_first)];
                        assert_eq!(original.near_branch_target(), base + 0x42);
                        let mut decoder = Decoder::with_ip(
                            64,
                            &image.bytes()[relocated_offset..],
                            relocated_address,
                            DecoderOptions::NONE,
                        );
                        let first = decoder.decode();
                        let mut transfers = vec![first];
                        for _ in 0..2 {
                            if transfers.last().unwrap().op0_kind() == OpKind::Memory {
                                break;
                            }
                            transfers.push(decoder.decode());
                        }
                        let indirect = *transfers.last().unwrap();
                        assert_eq!(indirect.op0_kind(), OpKind::Memory, "{}", case.name);
                        assert_eq!(
                            indirect.code(),
                            if original.mnemonic() == Mnemonic::Call {
                                Code::Call_rm64
                            } else {
                                Code::Jmp_rm64
                            },
                            "{}",
                            case.name
                        );
                        let relay = relay_for_transfer(&image, destination, &indirect, base + 0x42);
                        for pc in first.ip()..indirect.next_ip() {
                            assert_eq!(logical_pc(&image, pc), Some(original.ip()));
                        }
                        match original.mnemonic() {
                            Mnemonic::Je | Mnemonic::Jne => {
                                assert_eq!(
                                    first.mnemonic(),
                                    if original.mnemonic() == Mnemonic::Je {
                                        Mnemonic::Jne
                                    } else {
                                        Mnemonic::Je
                                    }
                                );
                                assert_eq!(first.near_branch_target(), indirect.next_ip());
                            }
                            Mnemonic::Loop
                            | Mnemonic::Loope
                            | Mnemonic::Loopne
                            | Mnemonic::Jrcxz
                            | Mnemonic::Jecxz => {
                                assert_eq!(first.mnemonic(), original.mnemonic());
                                assert_eq!(first.near_branch_target(), indirect.ip());
                                assert_eq!(transfers[1].code(), Code::Jmp_rel8_64);
                                assert_eq!(transfers[1].near_branch_target(), indirect.next_ip());
                            }
                            Mnemonic::Call | Mnemonic::Jmp => assert_eq!(transfers.len(), 1),
                            _ => unreachable!(),
                        }
                        let terminal = decode_terminal(&mut decoder);
                        assert_eq!(terminal.code(), Code::Jmp_rel32_64);
                        assert_eq!(terminal.near_branch_target(), return_stub);
                        assert_eq!(relay + BRANCH_RELAY_BYTES as u64, return_stub);
                    }
                }
            }
        }

        #[test]
        fn branch_relay_grouping_is_deterministic_for_shared_and_mixed_targets() {
            struct Fixture {
                name: &'static str,
                observing: &'static [u8],
                replacing: &'static [u8],
                target_offsets: [u64; 2],
                shared: bool,
            }
            let fixtures = [
                Fixture {
                    name: "shared_external",
                    observing: &[0x75, 0x40, 0x74, 0x3e, 0x90],
                    replacing: &[0x90, 0x75, 0x3f, 0x74, 0x3d],
                    target_offsets: [0x42, 0x42],
                    shared: true,
                },
                Fixture {
                    name: "entry_then_external",
                    observing: &[0x75, 0xfe, 0x74, 0x3e, 0x90],
                    replacing: &[0x90, 0x75, 0xfd, 0x74, 0x3d],
                    target_offsets: [0, 0x42],
                    shared: false,
                },
                Fixture {
                    name: "external_then_entry",
                    observing: &[0x75, 0x40, 0x74, 0xfc, 0x90],
                    replacing: &[0x90, 0x75, 0x3f, 0x74, 0xfb],
                    target_offsets: [0x42, 0],
                    shared: false,
                },
            ];
            let base = 0x20_0000;
            let destination = 0x4_0000_0000;

            for fixture in fixtures {
                for (replace_first, stops) in [(false, false), (true, false), (true, true)] {
                    let code = if replace_first {
                        fixture.replacing
                    } else {
                        fixture.observing
                    };
                    let plan = make_mode_plan(code, base, replace_first, stops);
                    let image = plan.emit_at(destination).unwrap();
                    let (relocated_offset, relocated_address, return_stub) =
                        relocated_bounds(&image, destination);
                    let originals: Vec<_> = Decoder::with_ip(64, code, base, DecoderOptions::NONE)
                        .into_iter()
                        .skip(usize::from(replace_first))
                        .filter(|instruction| instruction.op0_kind() == OpKind::NearBranch64)
                        .collect();
                    assert_eq!(originals.len(), 2, "{}", fixture.name);
                    let mut decoder = Decoder::with_ip(
                        64,
                        &image.bytes()[relocated_offset..],
                        relocated_address,
                        DecoderOptions::NONE,
                    );
                    let mut relays = Vec::new();
                    for (original, target_offset) in originals.iter().zip(fixture.target_offsets) {
                        assert_eq!(original.near_branch_target(), base + target_offset);
                        let conditional = decoder.decode();
                        let indirect = decoder.decode();
                        assert!(matches!(
                            conditional.mnemonic(),
                            Mnemonic::Je | Mnemonic::Jne
                        ));
                        assert_eq!(conditional.near_branch_target(), indirect.next_ip());
                        assert_eq!(indirect.code(), Code::Jmp_rm64);
                        let relay = relay_for_transfer(
                            &image,
                            destination,
                            &indirect,
                            base + target_offset,
                        );
                        for pc in conditional.ip()..indirect.next_ip() {
                            assert_eq!(logical_pc(&image, pc), Some(original.ip()));
                        }
                        relays.push(relay);
                    }
                    if fixture.shared {
                        assert_eq!(relays[0], relays[1], "{}", fixture.name);
                        assert_eq!(relays[0] + BRANCH_RELAY_BYTES as u64, return_stub);
                    } else {
                        assert_eq!(
                            relays[0] + BRANCH_RELAY_BYTES as u64,
                            relays[1],
                            "{}",
                            fixture.name
                        );
                        assert_eq!(relays[1] + BRANCH_RELAY_BYTES as u64, return_stub);
                    }
                    let terminal = decode_terminal(&mut decoder);
                    assert_eq!(terminal.code(), Code::Jmp_rel32_64);
                    assert_eq!(terminal.near_branch_target(), return_stub);
                }
            }
        }

        #[test]
        fn mixed_short_jcc_and_call_get_distinct_relays_in_public_plans() {
            let base = 0x20_0000;
            let destination = 0x4_0000_0000;
            let observing = [0x75, 0x40, 0xe8, 0xf9, 0, 0, 0];
            let replacing = [0x90, 0x75, 0x3f, 0xe8, 0xf8, 0, 0, 0];

            for (replace_first, stops) in [(false, false), (true, false), (true, true)] {
                let code = if replace_first {
                    replacing.as_slice()
                } else {
                    observing.as_slice()
                };
                let plan = make_mode_plan(code, base, replace_first, stops);
                assert_eq!(plan.displaced_len(), code.len());
                let image = plan.emit_at(destination).unwrap();
                let (relocated_offset, relocated_address, return_stub) =
                    relocated_bounds(&image, destination);
                let mut decoder = Decoder::with_ip(
                    64,
                    &image.bytes()[relocated_offset..],
                    relocated_address,
                    DecoderOptions::NONE,
                );

                let conditional = decoder.decode();
                let jcc_transfer = decoder.decode();
                let call_transfer = decoder.decode();
                assert_eq!(conditional.mnemonic(), Mnemonic::Je);
                assert_eq!(conditional.near_branch_target(), jcc_transfer.next_ip());
                assert_eq!(jcc_transfer.code(), Code::Jmp_rm64);
                assert_eq!(call_transfer.code(), Code::Call_rm64);
                let original_jcc = base + u64::from(replace_first);
                let original_call = original_jcc + 2;
                for pc in conditional.ip()..jcc_transfer.next_ip() {
                    assert_eq!(logical_pc(&image, pc), Some(original_jcc));
                }
                for pc in call_transfer.ip()..call_transfer.next_ip() {
                    assert_eq!(logical_pc(&image, pc), Some(original_call));
                }

                let targets = [base + 0x42, base + 0x100];
                let mut relays = Vec::new();
                for (transfer, target) in [(jcc_transfer, targets[0]), (call_transfer, targets[1])]
                {
                    relays.push(relay_for_transfer(&image, destination, &transfer, target));
                }
                assert_eq!(relays[0] + BRANCH_RELAY_BYTES as u64, relays[1]);
                assert_eq!(relays[1] + BRANCH_RELAY_BYTES as u64, return_stub);
                let terminal = decoder.decode();
                assert_eq!(terminal.code(), Code::Jmp_rel32_64);
                assert_eq!(terminal.near_branch_target(), return_stub);
            }
        }

        #[test]
        fn near_entry_backedges_do_not_add_relay_or_change_encoding() {
            let base = 0x20_0000;
            let destination = base + 0x10_0000;
            for code in [
                &[0xe9, 0xfb, 0xff, 0xff, 0xff][..],
                &[0xe8, 0xfb, 0xff, 0xff, 0xff],
                &[0x75, 0xfe, 0x90, 0x90, 0x90],
                &[0xe2, 0xfe, 0x90, 0x90, 0x90],
            ] {
                let plan = make_plan(code, base, false);
                let normalized =
                    super::super::relocation_encoder_instructions(&plan.instructions, Some(base))
                        .unwrap();
                let original_encoding = iced_x86::BlockEncoder::encode(
                    64,
                    iced_x86::InstructionBlock::new(&normalized, destination),
                    iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS
                        | iced_x86::BlockEncoderOptions::RETURN_RELOC_INFOS,
                )
                .unwrap();
                assert!(original_encoding.reloc_infos.is_empty());
                let relocated = super::super::encode_relocated_block(
                    &plan.instructions,
                    destination,
                    Some(base),
                )
                .unwrap();
                assert!(relocated.branch_relays.is_empty());
                assert!(relocated.terminal_jump_offset.is_none());
                assert_eq!(relocated.encoded.code_buffer, original_encoding.code_buffer);
                assert_eq!(
                    relocated.encoded.new_instruction_offsets,
                    original_encoding.new_instruction_offsets
                );
            }
        }

        #[test]
        fn near_external_branches_keep_iced_bytes_and_offsets_in_all_plan_modes() {
            let cases = [
                (&[0xe9, 0x3d, 0, 0, 0][..], &[0x90, 0xe9, 0x3c, 0, 0, 0][..]),
                (&[0xe8, 0x3d, 0, 0, 0][..], &[0x90, 0xe8, 0x3c, 0, 0, 0][..]),
                (
                    &[0x75, 0x40, 0x90, 0x90, 0x90][..],
                    &[0x90, 0x75, 0x3f, 0x90, 0x90][..],
                ),
                (
                    &[0xe2, 0x40, 0x90, 0x90, 0x90][..],
                    &[0x90, 0xe2, 0x3f, 0x90, 0x90][..],
                ),
            ];
            let base = 0x20_0000;
            let destination = base + 0x10_0000;

            for (observing, replacing) in cases {
                for (replace_first, stops) in [(false, false), (true, false), (true, true)] {
                    let code = if replace_first { replacing } else { observing };
                    let plan = make_mode_plan(code, base, replace_first, stops);
                    let image = plan.emit_at(destination).unwrap();
                    let layout = image.layout();
                    let (relocated_offset, relocated_address, _) =
                        relocated_bounds(&image, destination);
                    let instructions = &plan.instructions[usize::from(replace_first)..];
                    let observing_entry = (!replace_first).then_some(base);
                    let normalized = super::super::relocation_encoder_instructions(
                        instructions,
                        observing_entry,
                    )
                    .unwrap();
                    let expected = iced_x86::BlockEncoder::encode(
                        64,
                        iced_x86::InstructionBlock::new(&normalized, relocated_address),
                        iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS
                            | iced_x86::BlockEncoderOptions::RETURN_RELOC_INFOS,
                    )
                    .unwrap();
                    assert!(expected.reloc_infos.is_empty());
                    let relocated = super::super::encode_relocated_block(
                        instructions,
                        relocated_address,
                        observing_entry,
                    )
                    .unwrap();
                    assert!(relocated.branch_relays.is_empty());
                    assert!(relocated.terminal_jump_offset.is_none());
                    assert_eq!(relocated.encoded.code_buffer, expected.code_buffer);
                    assert_eq!(
                        relocated.encoded.new_instruction_offsets,
                        expected.new_instruction_offsets
                    );
                    assert_eq!(
                        &image.bytes()[relocated_offset..relocated_offset + layout.relocated_len],
                        expected.code_buffer
                    );
                }
            }
        }

        #[test]
        fn relay_selection_uses_relocations_not_equal_immediates_or_continuation_identity() {
            let base = 0x20_0000_u64;
            let destination = 0x4_0000_0000;
            let external = base + 0x42;

            for (replace_first, stops) in [(false, false), (true, false), (true, true)] {
                let mut code = if replace_first {
                    vec![0x90, 0x75, 0x3f, 0x48, 0xb8]
                } else {
                    vec![0x75, 0x40, 0x48, 0xb8]
                };
                code.extend_from_slice(&external.to_le_bytes());
                let plan = make_mode_plan(&code, base, replace_first, stops);
                assert_eq!(plan.displaced_len(), code.len());
                let image = plan.emit_at(destination).unwrap();
                let (offset, start, return_stub) = relocated_bounds(&image, destination);
                let mut decoder =
                    Decoder::with_ip(64, &image.bytes()[offset..], start, DecoderOptions::NONE);
                let conditional = decoder.decode();
                let transfer = decoder.decode();
                let mov = decoder.decode();
                assert_eq!(conditional.near_branch_target(), transfer.next_ip());
                assert_eq!(transfer.code(), Code::Jmp_rm64);
                assert_eq!(mov.mnemonic(), Mnemonic::Mov);
                assert_eq!(mov.immediate64(), external);
                let relay = relay_for_transfer(&image, destination, &transfer, external);
                assert_eq!(relay + BRANCH_RELAY_BYTES as u64, return_stub);
                let terminal = decode_terminal(&mut decoder);
                assert_eq!(terminal.code(), Code::Jmp_rel32_64);
                assert_eq!(terminal.near_branch_target(), return_stub);

                let continuation_code = if replace_first {
                    &[0x90, 0x75, 0x02, 0x90, 0x90][..]
                } else {
                    &[0x75, 0x03, 0x90, 0x90, 0x90][..]
                };
                let continuation_plan =
                    make_mode_plan(continuation_code, base, replace_first, stops);
                let continuation_image = continuation_plan.emit_at(destination).unwrap();
                let (continuation_offset, continuation_start, continuation_stub) =
                    relocated_bounds(&continuation_image, destination);
                assert_eq!(continuation_plan.return_address(), base + 5);
                let mut continuation_decoder = Decoder::with_ip(
                    64,
                    &continuation_image.bytes()[continuation_offset..],
                    continuation_start,
                    DecoderOptions::NONE,
                );
                let conditional = continuation_decoder.decode();
                let transfer = continuation_decoder.decode();
                assert_eq!(conditional.near_branch_target(), transfer.next_ip());
                let relay = relay_for_transfer(
                    &continuation_image,
                    destination,
                    &transfer,
                    continuation_plan.return_address(),
                );
                assert_eq!(relay + BRANCH_RELAY_BYTES as u64, continuation_stub);
                let terminal = decode_terminal(&mut continuation_decoder);
                assert_eq!(terminal.near_branch_target(), continuation_stub);
            }
        }

        #[test]
        fn far_branch_relays_preserve_entry_and_external_destinations() {
            let base = 0x20_0000;
            let destination = 0x4_0000_0000;
            let plan = make_plan(&[0x75, 0xfe, 0x74, 0x7f, 0x90], base, false);
            let image = plan.emit_at(destination).unwrap();
            let mut decoder = relocated(&image, destination);
            assert_eq!(decoder.decode().mnemonic(), Mnemonic::Je);
            let entry_transfer = decoder.decode();
            assert_eq!(decoder.decode().mnemonic(), Mnemonic::Jne);
            let other_transfer = decoder.decode();
            for (transfer, target) in [(entry_transfer, base), (other_transfer, base + 4 + 0x7f)] {
                assert_eq!(transfer.code(), Code::Jmp_rm64);
                let literal = (transfer.ip_rel_memory_address() - destination) as usize;
                let relay =
                    u64::from_le_bytes(image.bytes()[literal..literal + 8].try_into().unwrap());
                assert_branch_relay(&image, destination, relay, target);
            }
        }

        #[test]
        fn preserves_replace_first_omitted_and_retained_targets() {
            let base = 0x20_0000;
            for eip in [false, true] {
                for target in [base, base + 3] {
                    // The omitted NOP remains an external branch/memory target;
                    // the retained LEA's own address must also remain original.
                    let mut code = vec![0x90, 0x75, 0xfd];
                    code.extend(memory_code(&[0x48, 0x8d, 0x05], eip, base + 3, target));
                    let plan = make_plan(&code, base, true);
                    let original = plan.instructions.clone();
                    let destination = base + 0x10_0000;
                    let image = plan.emit_at(destination).unwrap();
                    let mut decoder = relocated(&image, destination);
                    let branch = decoder.decode();
                    assert_eq!(branch.near_branch_target(), base);
                    let memory = decoder.decode();
                    assert_memory(&original[2], &memory);
                    assert_eq!(logical_pc(&image, branch.ip()), Some(base + 1));
                    assert_eq!(logical_pc(&image, memory.ip()), Some(base + 3));
                    assert_eq!(plan.instructions, original);
                }
            }
        }

        #[test]
        fn preserves_memory_and_pc_mappings_with_far_branch_literals() {
            let base = 0x40;
            for target in [0, 1, 2] {
                for alignment in 0..8 {
                    let mut code = vec![
                        0x75,
                        i8::try_from(target as i64 - (base + 2) as i64).unwrap() as u8,
                    ];
                    code.extend(memory_code(&[0x48, 0x8d, 0x05], false, base + 2, base));
                    let plan = make_plan(&code, base, false);
                    let original = plan.instructions.clone();
                    let destination = 0x4_0000_0000 + alignment;
                    let image = plan.emit_at(destination).unwrap();
                    let mut decoder = relocated(&image, destination);
                    let branch = decoder.decode();
                    let indirect = decoder.decode();
                    let memory = decoder.decode();
                    let terminal = decoder.decode();
                    assert_eq!(branch.mnemonic(), Mnemonic::Je);
                    assert_eq!(branch.near_branch_target(), memory.ip());
                    assert_eq!(indirect.mnemonic(), Mnemonic::Jmp);
                    assert_eq!(indirect.op0_kind(), OpKind::Memory);
                    let literal = indirect.ip_rel_memory_address();
                    let offset = usize::try_from(literal - destination).unwrap();
                    let relay =
                        u64::from_le_bytes(image.bytes()[offset..offset + 8].try_into().unwrap());
                    assert_branch_relay(&image, destination, relay, target);
                    assert_memory(&original[1], &memory);
                    assert_eq!(terminal.code(), Code::Jmp_rel32_64);
                    let return_stub = destination
                        + (image.layout().instrumentation_len
                            + image.layout().restore_len
                            + image.layout().relocated_len) as u64;
                    assert_eq!(terminal.near_branch_target(), return_stub);
                    assert!(literal >= terminal.next_ip());
                    assert!(literal + 8 <= return_stub);
                    for pc in branch.ip()..memory.ip() {
                        assert_eq!(logical_pc(&image, pc), Some(base));
                    }
                    for pc in memory.ip()..memory.next_ip() {
                        assert_eq!(logical_pc(&image, pc), Some(base + 2));
                    }
                    for pc in terminal.ip()..terminal.next_ip() {
                        assert_eq!(logical_pc(&image, pc), Some(plan.return_address()));
                    }
                    assert_eq!(relay + BRANCH_RELAY_BYTES as u64, return_stub);
                    for pc in terminal.next_ip()..return_stub {
                        let expected = (relay..relay + BRANCH_RELAY_CODE.len() as u64)
                            .contains(&pc)
                            .then_some(target);
                        assert_eq!(logical_pc(&image, pc), expected);
                    }
                    assert_eq!(plan.instructions, original);
                }
            }
        }

        #[test]
        fn refuses_unreachable_original_memory_instead_of_rebinding_it() {
            let base = 0x1_0000_1000;
            let code = memory_code(&[0x48, 0x8d, 0x05], false, base, base);
            let plan = make_plan(&code, base, false);
            assert!(matches!(
                plan.emit_at(0x4_0000_0000),
                Err(TrampolineError::Encoding { .. })
            ));
        }

        #[test]
        fn normalization_preserves_direct_branch_operand_widths() {
            let code = memory_code(&[0x48, 0x8d, 0x05], false, 0, 0);
            let memory = Decoder::with_ip(64, &code, 0, DecoderOptions::NONE).decode();
            let mut original = vec![memory];
            for (index, code) in [Code::Jmp_rel16, Code::Jmp_rel32_32, Code::Jmp_rel32_64]
                .into_iter()
                .enumerate()
            {
                let mut branch = Instruction::with_branch(code, 0).unwrap();
                branch.set_ip(index as u64 + 1);
                original.push(branch);
            }
            // Synthetic metadata covers operand widths that a 64-bit decoder
            // need not emit; actual executable relocation is tested above.
            for observing_entry in [None, Some(0)] {
                let normalized =
                    super::super::relocation_encoder_instructions(&original, observing_entry)
                        .unwrap();
                assert_memory(&original[0], &normalized[0]);
                assert!(![0, 1, 2, 3].contains(&normalized[0].ip()));
                assert!(u16::try_from(normalized[0].ip()).is_ok());
                for (before, after) in original[1..].iter().zip(&normalized[1..]) {
                    assert_eq!(after.op0_kind(), before.op0_kind());
                    assert_eq!(after.code(), before.code());
                    assert_eq!(
                        after.near_branch_target(),
                        observing_entry.unwrap_or(normalized[0].ip())
                    );
                    assert_eq!(after.ip(), before.ip());
                }
            }
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn reencodes_rip_relative_memory_for_the_trampoline_address() {
        use iced_x86::Decoder;
        use iced_x86::DecoderOptions;

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
        use iced_x86::Decoder;
        use iced_x86::DecoderOptions;

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
    #[test]
    fn maps_each_consecutive_expanded_branch_to_its_original_pc() {
        let base = 0x40_0000_u64;
        for (branches, expanded_len) in [
            ([0x74, 0x80, 0x75, 0x80, 0x74, 0x80], 8_u64),
            ([0xEB, 0x80, 0xEB, 0x80, 0xEB, 0x80], 6_u64),
        ] {
            let trampoline_address = 0x2_0000_0000;
            let plan = plan(&branches, base).unwrap();
            let image = plan.emit_at(trampoline_address).unwrap();
            let relocated_address = trampoline_address
                + image.layout().instrumentation_len as u64
                + image.layout().restore_len as u64;
            let second = image
                .program_counter_mappings()
                .iter()
                .find(|mapping| mapping.logical_address() == base + 2)
                .unwrap();
            let third = image
                .program_counter_mappings()
                .iter()
                .find(|mapping| mapping.logical_address() == base + 4)
                .unwrap();

            assert_eq!(second.generated_start(), relocated_address + expanded_len);
            assert_eq!(
                third.generated_start(),
                relocated_address + 2 * expanded_len
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn far_tail_code_and_data_have_distinct_pc_mappings() {
        let base = 0x1_8000_0000_u64;
        let target = 0x1_1000_0000_u64;
        for call in [false, true] {
            let mut code = if call {
                vec![0xE8]
            } else {
                vec![0x85, 0xFF, 0x0F, 0x84]
            };
            let original_len = if call { 5 } else { 8 };
            let displacement =
                i32::try_from(i128::from(target) - i128::from(base + original_len)).unwrap();
            code.extend_from_slice(&displacement.to_le_bytes());
            let plan = plan(&code, base).unwrap();
            for start in [base + 0x7000_0000, 0x4_0000_0000] {
                // Exercise every pointer-table alignment, for both final returns.
                for alignment in 0..8 {
                    let address = start + alignment;
                    let image = plan.emit_at(address).unwrap();
                    let layout = image.layout();
                    let relocated = layout.instrumentation_len + layout.restore_len;
                    let return_offset = relocated + layout.relocated_len;
                    let terminal = relocated + if call { 6 } else { 10 };
                    let translate = |offset: usize| {
                        image
                            .program_counter_mappings()
                            .iter()
                            .find_map(|mapping| mapping.translate(address + offset as u64))
                    };
                    for offset in relocated..terminal {
                        let logical = if call || offset < relocated + 2 {
                            base
                        } else {
                            base + 2
                        };
                        assert_eq!(translate(offset), Some(logical));
                    }
                    assert_eq!(image.bytes()[terminal], 0xE9);
                    let displacement = i32::from_le_bytes(
                        image.bytes()[terminal + 1..terminal + 5]
                            .try_into()
                            .unwrap(),
                    );
                    assert_eq!(
                        i128::from(address + terminal as u64 + 5) + i128::from(displacement),
                        i128::from(address + return_offset as u64)
                    );
                    for offset in terminal..terminal + 5 {
                        assert_eq!(translate(offset), Some(plan.return_address()));
                    }
                    let relocated_address = address + relocated as u64;
                    let mut decoder = iced_x86::Decoder::with_ip(
                        64,
                        &image.bytes()[relocated..return_offset],
                        relocated_address,
                        iced_x86::DecoderOptions::NONE,
                    );
                    let transfer = loop {
                        let instruction = decoder.decode();
                        assert!(!instruction.is_invalid());
                        if matches!(
                            instruction.code(),
                            iced_x86::Code::Call_rm64 | iced_x86::Code::Jmp_rm64
                        ) {
                            break instruction;
                        }
                    };
                    let pool_offset =
                        usize::try_from(transfer.ip_rel_memory_address() - address).unwrap();
                    let relay = u64::from_le_bytes(
                        image.bytes()[pool_offset..pool_offset + 8]
                            .try_into()
                            .unwrap(),
                    );
                    let relay_offset = usize::try_from(relay - address).unwrap();
                    assert_eq!(relay_offset + super::BRANCH_RELAY_BYTES, return_offset);
                    assert_eq!(
                        &image.bytes()[relay_offset..relay_offset + super::BRANCH_RELAY_CODE.len()],
                        &super::BRANCH_RELAY_CODE
                    );
                    assert_eq!(
                        &image.bytes()[relay_offset + super::BRANCH_RELAY_CODE.len()
                            ..relay_offset + super::BRANCH_RELAY_BYTES],
                        &target.to_le_bytes()
                    );
                    for offset in terminal + 5..return_offset {
                        let expected = (relay_offset
                            ..relay_offset + super::BRANCH_RELAY_CODE.len())
                            .contains(&offset)
                            .then_some(target);
                        assert_eq!(translate(offset), expected, "tail offset {offset}");
                    }
                    assert_eq!(
                        &image.bytes()[return_offset - 8..return_offset],
                        &target.to_le_bytes()
                    );
                    assert!(pool_offset >= terminal + 5);
                    assert_eq!(pool_offset + 8, relay_offset);
                    assert!(
                        image.bytes()[terminal + 5..pool_offset]
                            .iter()
                            .all(|byte| *byte == 0xCC)
                    );
                    let return_code_len = if layout.return_len == 5 { 5 } else { 7 };
                    assert_eq!(
                        layout.return_len,
                        if start == base + 0x7000_0000 { 5 } else { 15 }
                    );
                    for offset in return_offset..return_offset + return_code_len {
                        assert_eq!(translate(offset), Some(plan.return_address()));
                    }
                    for offset in return_offset + return_code_len..image.bytes().len() {
                        assert_eq!(
                            translate(offset),
                            None,
                            "final return literal offset {offset}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn terminal_instruction_does_not_capture_low_application_targets() {
        let mut branch =
            iced_x86::Instruction::with_branch(iced_x86::Code::Jne_rel8_64, 1).unwrap();
        branch.set_ip(0);
        let mut jump = iced_x86::Instruction::with_branch(iced_x86::Code::Jmp_rel8_64, 2).unwrap();
        jump.set_ip(3);
        let address = 0x4_0000_0000;
        let relocated = super::encode_relocated_block(&[branch, jump], address, None).unwrap();
        assert!(relocated.terminal_jump_offset.is_some());
        assert_eq!(relocated.branch_relays.len(), 2);
        assert_eq!(
            relocated
                .branch_relays
                .iter()
                .map(|relay| relay.target)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        let encoded = relocated.encoded;
        let pool_targets: Vec<_> = encoded
            .reloc_infos
            .iter()
            .zip(&relocated.branch_relays)
            .map(|(info, relay)| {
                let offset = (info.address - address) as usize;
                assert_eq!(info.kind, iced_x86::RelocKind::Offset64);
                assert_eq!(
                    u64::from_le_bytes(encoded.code_buffer[offset..offset + 8].try_into().unwrap()),
                    address + relay.offset as u64
                );
                assert_eq!(
                    &encoded.code_buffer
                        [relay.offset..relay.offset + super::BRANCH_RELAY_CODE.len()],
                    &super::BRANCH_RELAY_CODE
                );
                u64::from_le_bytes(
                    encoded.code_buffer[relay.offset + super::BRANCH_RELAY_CODE.len()
                        ..relay.offset + super::BRANCH_RELAY_BYTES]
                        .try_into()
                        .unwrap(),
                )
            })
            .collect();
        assert_eq!(pool_targets, [1, 2]);
        assert_eq!(encoded.new_instruction_offsets, [u32::MAX, u32::MAX]);
    }

    #[test]
    fn branch_relay_rejects_malformed_final_offset64_slots() {
        fn encoded(buffer_len: usize, relocation_address: u64) -> iced_x86::BlockEncoderResult {
            iced_x86::BlockEncoderResult {
                rip: 0x100,
                code_buffer: vec![0; buffer_len],
                reloc_infos: vec![iced_x86::RelocInfo::new(
                    iced_x86::RelocKind::Offset64,
                    relocation_address,
                )],
                new_instruction_offsets: Vec::new(),
                constant_offsets: Vec::new(),
            }
        }

        let assert_encoding =
            |result: Result<Vec<super::BranchRelay>, TrampolineError>, text| match result {
                Err(TrampolineError::Encoding { message }) => {
                    assert!(
                        message.contains(text),
                        "{message:?} does not contain {text:?}"
                    );
                }
                _ => panic!("expected encoding refusal containing {text:?}"),
            };

        let mut before = encoded(16, 0xff);
        assert_encoding(
            super::append_branch_relays(&mut before, 0x100, 8),
            "precedes encoded block",
        );

        let mut overlapping = encoded(16, 0x104);
        assert_encoding(
            super::append_branch_relays(&mut overlapping, 0x100, 12),
            "overlaps executable instructions",
        );

        let mut truncated = encoded(16, 0x10c);
        assert_encoding(
            super::append_branch_relays(&mut truncated, 0x100, 8),
            "exceeds encoded block",
        );

        let mut range_overflow = encoded(16, u64::MAX - 3);
        assert_encoding(
            super::append_branch_relays(&mut range_overflow, 0, 8),
            "range overflow",
        );
    }

    #[test]
    fn branch_relay_layout_refuses_length_address_and_rel32_overflow() {
        let assert_encoding = |result: Result<(usize, i32), TrampolineError>, text| match result {
            Err(TrampolineError::Encoding { message }) => {
                assert!(
                    message.contains(text),
                    "{message:?} does not contain {text:?}"
                );
            }
            _ => panic!("expected encoding refusal containing {text:?}"),
        };

        assert_encoding(
            super::checked_branch_relay_layout(0, 0, usize::MAX, 0),
            "relay length overflow",
        );
        assert_encoding(
            super::checked_branch_relay_layout(0, usize::MAX, 1, 0),
            "relocated block length overflow",
        );
        assert!(matches!(
            super::checked_branch_relay_layout(u64::MAX - 8, 0, 1, 0),
            Err(TrampolineError::AddressNotRepresentable { .. })
        ));
        assert_encoding(
            super::checked_branch_relay_layout(0, i32::MAX as usize, 1, 0),
            "signed rel32 reach",
        );
        assert_encoding(
            super::checked_branch_relay_layout(0, 0, 1, super::BRANCH_RELAY_BYTES + 1),
            "terminal jump exceeds",
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod live {
        use core::arch::asm;
        use core::sync::atomic::AtomicBool;
        use core::sync::atomic::AtomicU64;
        use core::sync::atomic::Ordering;
        use std::os::fd::AsRawFd;
        use std::os::fd::FromRawFd;
        use std::os::fd::OwnedFd;
        use std::process::Child;
        use std::process::Command;
        use std::process::ExitStatus;
        use std::sync::Arc;
        use std::sync::Barrier;
        use std::sync::Mutex;
        use std::sync::MutexGuard;
        use std::thread;
        use std::time::Duration;
        use std::time::Instant;

        use super::HookContext;
        use super::InstructionScanner;
        use crate::patcher::PatchError;
        use crate::patcher::StalenessBudget;
        use crate::trampoline::HOOK_CONTEXT_STACK_PREFIX_BYTES;
        use crate::trampoline::HookSite;
        use crate::trampoline::InstalledHook;
        use crate::trampoline::SavedExtendedStateDescriptor;
        use crate::trampoline::TrampolineError;
        use crate::trampoline::translate_program_counter;

        const PAGE_BYTES: usize = 4096;
        const STALENESS_TICKS: u64 = 3_000;
        const PTRACE_CHILD_ENV: &str = "LITEINST2_PTRACE_STOP_CHILD_FD";
        const PTRACE_CHILD_TEST: &str =
            "trampoline::tests::live::ptrace_stopped_hook_executes_on_owned_stack";
        const PTRACE_EVENT_TIMEOUT: Duration = Duration::from_secs(10);
        const OWNED_STACK_BYTES: usize = 64 * 1024;
        const NT_X86_XSTATE: usize = 0x202;
        static TEST_LOCK: Mutex<()> = Mutex::new(());
        static CALLBACKS: AtomicU64 = AtomicU64::new(0);
        static LAST_IP: AtomicU64 = AtomicU64::new(0);
        static LAST_EXTENDED_ADDRESS: AtomicU64 = AtomicU64::new(0);
        static LAST_EXTENDED_LEN: AtomicU64 = AtomicU64::new(0);
        static LAST_EXTENDED_MASK: AtomicU64 = AtomicU64::new(0);
        static LAST_EXTENDED_FORMAT: AtomicU64 = AtomicU64::new(0);

        fn serial_guard() -> MutexGuard<'static, ()> {
            TEST_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
        static LAST_RDI: AtomicU64 = AtomicU64::new(0);

        unsafe extern "C" fn record_hook(context: *mut HookContext) {
            // SAFETY: generated code passes a live HookContext for this call.
            let context = unsafe { &*context };
            let extended = context.saved_extended_state();
            LAST_IP.store(context.instruction_pointer, Ordering::Relaxed);
            LAST_RDI.store(context.rdi, Ordering::Relaxed);
            LAST_EXTENDED_ADDRESS.store(extended.address(), Ordering::Relaxed);
            LAST_EXTENDED_LEN.store(extended.len(), Ordering::Relaxed);
            LAST_EXTENDED_MASK.store(extended.mask(), Ordering::Relaxed);
            LAST_EXTENDED_FORMAT.store(extended.format().raw(), Ordering::Relaxed);
            CALLBACKS.fetch_add(1, Ordering::Relaxed);
        }

        unsafe extern "C" fn replace_first_hook(context: *mut HookContext) {
            // SAFETY: generated code passes a unique mutable snapshot.
            unsafe {
                (*context).rax = 40;
            }
            CALLBACKS.fetch_add(1, Ordering::Relaxed);
        }

        unsafe extern "C" fn ptrace_replace_first_hook(context: *mut HookContext) {
            // SAFETY: generated code passes a unique mutable snapshot.
            unsafe {
                (*context).rax = 40;
                asm!("pxor xmm0, xmm0", out("xmm0") _, options(nostack, preserves_flags));
            }
        }

        unsafe extern "C" fn clobber_flags_hook(_context: *mut HookContext) {
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

        unsafe extern "C" fn clobber_xmm_hook(_context: *mut HookContext) {
            // SAFETY: XMM0 is caller-saved; the trampoline must restore it.
            unsafe {
                asm!("pxor xmm0, xmm0", out("xmm0") _, options(nostack, preserves_flags));
            }
            CALLBACKS.fetch_add(1, Ordering::Relaxed);
        }

        unsafe extern "C" fn clobber_ymm_hook(_context: *mut HookContext) {
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

        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default)]
        struct PtraceStopControl {
            entry_rip: u64,
            completion_rip: u64,
            owned_stack_top: u64,
            tracee_tid: u64,
            execute_address: u64,
            saved_extended_state: super::SavedExtendedStateLayout,
        }

        struct PtraceChild {
            child: Child,
            tracee_tid: Option<libc::pid_t>,
        }

        impl PtraceChild {
            fn new(child: Child) -> Self {
                Self {
                    child,
                    tracee_tid: None,
                }
            }

            fn set_tracee_tid(&mut self, tracee_tid: libc::pid_t) {
                assert!(tracee_tid > 0);
                self.tracee_tid = Some(tracee_tid);
            }

            fn wait_for_exit(&mut self) -> ExitStatus {
                let deadline = Instant::now() + PTRACE_EVENT_TIMEOUT;
                loop {
                    match self.child.try_wait().unwrap() {
                        Some(status) => return status,
                        None if Instant::now() < deadline => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        None => panic!("ptrace child process did not exit after tracee exit"),
                    }
                }
            }
        }

        impl Drop for PtraceChild {
            fn drop(&mut self) {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                let _ = self.child.kill();
                let deadline = Instant::now() + PTRACE_EVENT_TIMEOUT;
                while Instant::now() < deadline {
                    if let Some(tracee_tid) = self.tracee_tid {
                        let mut status = 0;
                        // SAFETY: tracee_tid, when present, came from this
                        // owned child. Drain any terminal ptrace notification
                        // so the process leader can become waitable.
                        let _ = unsafe {
                            libc::waitpid(tracee_tid, &mut status, libc::WNOHANG | libc::__WALL)
                        };
                    }
                    match self.child.try_wait() {
                        Ok(Some(_)) | Err(_) => return,
                        Ok(None) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            }
        }

        fn write_all_fd(fd: libc::c_int, bytes: &[u8]) {
            let mut written = 0;
            while written < bytes.len() {
                // SAFETY: bytes names a live readable slice and fd is the
                // inherited control-pipe writer.
                let result = unsafe {
                    libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written)
                };
                assert!(result > 0, "control-pipe write failed");
                written += result as usize;
            }
        }

        fn read_control_fd(fd: libc::c_int) -> PtraceStopControl {
            let mut control = PtraceStopControl::default();
            // SAFETY: control is plain repr(C) integer storage.
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    (&raw mut control).cast::<u8>(),
                    core::mem::size_of::<PtraceStopControl>(),
                )
            };
            let deadline = Instant::now() + PTRACE_EVENT_TIMEOUT;
            let mut received = 0;
            while received < bytes.len() {
                if Instant::now() >= deadline {
                    panic!("ptrace child did not publish its control record");
                }
                let mut pollfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: pollfd names one initialized descriptor record.
                let polled = unsafe { libc::poll(&mut pollfd, 1, 20) };
                assert!(polled >= 0, "control-pipe poll failed");
                if polled == 0 {
                    continue;
                }
                // SAFETY: the remaining slice is writable and fd is readable.
                let amount = unsafe {
                    libc::read(
                        fd,
                        bytes[received..].as_mut_ptr().cast(),
                        bytes.len() - received,
                    )
                };
                if amount == 0 {
                    panic!("ptrace child closed its control pipe early");
                }
                assert!(amount > 0, "control-pipe read failed");
                received += amount as usize;
            }
            control
        }

        fn waitpid_event(
            tracee_tid: libc::pid_t,
            phase: &str,
            allow_not_yet_traced: bool,
        ) -> libc::c_int {
            let deadline = Instant::now() + PTRACE_EVENT_TIMEOUT;
            loop {
                let mut status = 0;
                // SAFETY: tracee_tid names the ptraced child thread and status
                // is writable. __WALL is required because Rust's test harness
                // runs each test in a non-leader thread.
                let result =
                    unsafe { libc::waitpid(tracee_tid, &mut status, libc::WNOHANG | libc::__WALL) };
                if result == tracee_tid {
                    return status;
                }
                if result == -1
                    && allow_not_yet_traced
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                assert_eq!(result, 0, "waitpid failed during {phase}");
                if Instant::now() >= deadline {
                    panic!("ptrace child timed out during {phase}");
                }
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn ptrace_getregs(pid: libc::pid_t) -> libc::user_regs_struct {
            // SAFETY: zero is a valid initial byte pattern for the output.
            let mut registers: libc::user_regs_struct = unsafe { core::mem::zeroed() };
            // SAFETY: child is ptrace-stopped and registers is writable.
            let result = unsafe {
                libc::ptrace(
                    libc::PTRACE_GETREGS,
                    pid,
                    core::ptr::null_mut::<libc::c_void>(),
                    (&raw mut registers).cast::<libc::c_void>(),
                )
            };
            assert_eq!(result, 0, "PTRACE_GETREGS failed");
            registers
        }

        fn ptrace_peek_u64(pid: libc::pid_t, address: u64) -> u64 {
            assert_eq!(address % core::mem::size_of::<u64>() as u64, 0);
            // SAFETY: errno is thread-local and setting it to zero is required
            // to distinguish a valid all-ones word from PTRACE_PEEKDATA error.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: the child is ptrace-stopped and address is an aligned
            // word in its authenticated owned-stack mapping.
            let word = unsafe {
                libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    pid,
                    address as usize as *mut libc::c_void,
                    core::ptr::null_mut::<libc::c_void>(),
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            assert!(word != -1 || errno == 0, "PTRACE_PEEKDATA failed");
            word as u64
        }

        fn ptrace_setregs(pid: libc::pid_t, registers: &libc::user_regs_struct) {
            // SAFETY: child is ptrace-stopped and registers names a complete set.
            let result = unsafe {
                libc::ptrace(
                    libc::PTRACE_SETREGS,
                    pid,
                    core::ptr::null_mut::<libc::c_void>(),
                    (registers as *const libc::user_regs_struct)
                        .cast_mut()
                        .cast::<libc::c_void>(),
                )
            };
            assert_eq!(result, 0, "PTRACE_SETREGS failed");
        }

        fn ptrace_get_xstate(pid: libc::pid_t) -> Vec<u8> {
            let mut bytes = vec![0_u8; 64 * 1024];
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            // SAFETY: child is ptrace-stopped and iov names writable storage.
            let result = unsafe {
                libc::ptrace(
                    libc::PTRACE_GETREGSET,
                    pid,
                    NT_X86_XSTATE as *mut libc::c_void,
                    (&raw mut iov).cast::<libc::c_void>(),
                )
            };
            assert_eq!(result, 0, "PTRACE_GETREGSET NT_X86_XSTATE failed");
            assert!(iov.iov_len >= 576 && iov.iov_len <= bytes.len());
            bytes.truncate(iov.iov_len);
            bytes
        }

        fn ptrace_set_xstate(pid: libc::pid_t, bytes: &mut [u8]) {
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            // SAFETY: child is ptrace-stopped and iov names the complete image.
            let result = unsafe {
                libc::ptrace(
                    libc::PTRACE_SETREGSET,
                    pid,
                    NT_X86_XSTATE as *mut libc::c_void,
                    (&raw mut iov).cast::<libc::c_void>(),
                )
            };
            assert_eq!(result, 0, "PTRACE_SETREGSET NT_X86_XSTATE failed");
            assert_eq!(iov.iov_len, bytes.len());
        }

        fn ptrace_continue(pid: libc::pid_t) {
            // SAFETY: child is ptrace-stopped; null data suppresses the stop signal.
            let result = unsafe {
                libc::ptrace(
                    libc::PTRACE_CONT,
                    pid,
                    core::ptr::null_mut::<libc::c_void>(),
                    core::ptr::null_mut::<libc::c_void>(),
                )
            };
            assert_eq!(result, 0, "PTRACE_CONT failed");
        }

        fn assert_completion_registers(
            entry: &libc::user_regs_struct,
            completion: &libc::user_regs_struct,
            expected_rip: u64,
            expected_rsp: u64,
        ) {
            assert_eq!(completion.rip, expected_rip);
            assert_eq!(completion.rsp, expected_rsp);
            assert_eq!(completion.rax, 40);
            assert_eq!(completion.r15, entry.r15);
            assert_eq!(completion.r14, entry.r14);
            assert_eq!(completion.r13, entry.r13);
            assert_eq!(completion.r12, entry.r12);
            assert_eq!(completion.rbp, entry.rbp);
            assert_eq!(completion.rbx, entry.rbx);
            assert_eq!(completion.r11, entry.r11);
            assert_eq!(completion.r10, entry.r10);
            assert_eq!(completion.r9, entry.r9);
            assert_eq!(completion.r8, entry.r8);
            assert_eq!(completion.rcx, entry.rcx);
            assert_eq!(completion.rdx, entry.rdx);
            assert_eq!(completion.rsi, entry.rsi);
            assert_eq!(completion.rdi, entry.rdi);
            assert_eq!(completion.orig_rax, entry.orig_rax);
            assert_eq!(completion.eflags, entry.eflags);
            assert_eq!(completion.cs, entry.cs);
            assert_eq!(completion.ss, entry.ss);
            assert_eq!(completion.ds, entry.ds);
            assert_eq!(completion.es, entry.es);
            assert_eq!(completion.fs, entry.fs);
            assert_eq!(completion.gs, entry.gs);
            assert_eq!(completion.fs_base, entry.fs_base);
            assert_eq!(completion.gs_base, entry.gs_base);
        }

        fn ptrace_stopped_child(control_fd: libc::c_int) -> ! {
            let mapping = DualMapping::new();
            let offset = 448;
            let code = [0x31, 0xC0, 0xFF, 0xC0, 0x90, 0xC3, 0x90, 0x90];
            mapping.write(offset, &code);
            let scanner = InstructionScanner::default();
            let address = mapping.executable_address(offset);
            let scan = scanner.scan(&code, address).unwrap();
            let arena = crate::trampoline::TrampolineArena::allocate_near(address, 2).unwrap();
            // SAFETY: this child owns both aliases, has no competing accessor,
            // and its parent will authenticate both generated stops.
            let hook = unsafe {
                InstalledHook::install_replacing_first_in_arena_quiescent_with_ptrace_stops(
                    HookSite::new(
                        &scanner,
                        &scan,
                        &code,
                        address,
                        address,
                        mapping.writable_address(offset),
                    ),
                    ptrace_replace_first_hook,
                    &arena,
                )
                .unwrap()
            };
            // SAFETY: no other thread accesses the synthetic code mapping.
            assert!(unsafe { hook.activate_quiescent() }.unwrap());
            // SAFETY: anonymous stack mapping with no fixed address.
            let owned_stack = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    OWNED_STACK_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
                    -1,
                    0,
                )
            };
            assert_ne!(owned_stack, libc::MAP_FAILED);
            let owned_stack_top = owned_stack as usize + OWNED_STACK_BYTES;
            assert_eq!(owned_stack_top % 64, 0);
            let control = PtraceStopControl {
                entry_rip: hook.trampoline().ptrace_entry_stop_rip().unwrap(),
                completion_rip: hook.trampoline().ptrace_completion_stop_rip().unwrap(),
                owned_stack_top: owned_stack_top as u64,
                // SAFETY: gettid has no pointer arguments and cannot fail for
                // the calling thread.
                tracee_tid: unsafe { libc::syscall(libc::SYS_gettid) as u64 },
                execute_address: address,
                saved_extended_state: hook.trampoline().layout().saved_extended_state,
            };
            // SAFETY: control is plain initialized repr(C) integer storage.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&raw const control).cast::<u8>(),
                    core::mem::size_of::<PtraceStopControl>(),
                )
            };
            write_all_fd(control_fd, bytes);
            // SAFETY: the complete control record is now in the pipe and the
            // child no longer needs its inherited writer.
            assert_eq!(unsafe { libc::close(control_fd) }, 0);
            // SAFETY: the subprocess's direct parent is the intended tracer.
            assert_eq!(
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_TRACEME,
                        0,
                        core::ptr::null_mut::<libc::c_void>(),
                        core::ptr::null_mut::<libc::c_void>(),
                    )
                },
                0
            );
            // SAFETY: SIGSTOP establishes the parent's initial ptrace stop.
            assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
            // SAFETY: the active synthetic bytes implement extern C fn() -> u32.
            let function: unsafe extern "C" fn() -> u32 =
                unsafe { core::mem::transmute(address as usize) };
            let result = unsafe { function() };
            // SAFETY: the isolated child reports the exact execution result.
            unsafe { libc::_exit(if result == 41 { 41 } else { 121 }) }
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
            hook: unsafe extern "C" fn(*mut HookContext),
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
            LAST_EXTENDED_ADDRESS.store(0, Ordering::Relaxed);
            LAST_EXTENDED_LEN.store(0, Ordering::Relaxed);
            LAST_EXTENDED_MASK.store(0, Ordering::Relaxed);
            LAST_EXTENDED_FORMAT.store(0, Ordering::Relaxed);

            let mapping = DualMapping::new();
            let offset = 60;
            let code = [0xB8, 7, 0, 0, 0, 0x01, 0xF8, 0xC3];
            let hook = install(&mapping, offset, &code, 0, record_hook);
            assert_eq!(
                hook.trampoline()
                    .translate_program_counter(hook.trampoline().relocated_tail_address()),
                Some(mapping.executable_address(offset))
            );
            assert_eq!(
                translate_program_counter(hook.trampoline().relocated_tail_address()),
                Some(mapping.executable_address(offset))
            );
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
            let extended_layout = hook.trampoline().layout().saved_extended_state;
            assert!(!extended_layout.is_empty());
            assert_eq!(
                LAST_EXTENDED_LEN.load(Ordering::Relaxed),
                extended_layout.len()
            );
            assert_eq!(
                LAST_EXTENDED_MASK.load(Ordering::Relaxed),
                extended_layout.mask()
            );
            assert_eq!(
                LAST_EXTENDED_FORMAT.load(Ordering::Relaxed),
                extended_layout.format().raw()
            );
            let saved_address = LAST_EXTENDED_ADDRESS.load(Ordering::Relaxed);
            let alignment = extended_layout
                .format()
                .required_alignment()
                .expect("generated trampoline must publish an admitted saved-state format");
            assert_ne!(saved_address, 0);
            assert_eq!(saved_address % alignment, 0);
            assert!(extended_layout.image_len() <= extended_layout.len());
            for (index, component) in extended_layout.components().iter().enumerate() {
                assert!(component.xfeature().is_power_of_two());
                assert_ne!(extended_layout.mask() & component.xfeature(), 0);
                assert!(component.offset() >= 576);
                assert!(component.size() > 0);
                assert!(component.offset() + component.size() <= extended_layout.image_len());
                for prior in &extended_layout.components()[..index] {
                    assert!(
                        component.offset() >= prior.offset() + prior.size()
                            || prior.offset() >= component.offset() + component.size()
                    );
                }
            }
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
        fn arena_hook_replaces_a_short_first_instruction_and_runs_the_tail() {
            let _guard = serial_guard();
            CALLBACKS.store(0, Ordering::Relaxed);

            let mapping = DualMapping::new();
            let offset = 256;
            // xor eax,eax; inc eax; nop; ret; padding
            let code = [0x31, 0xC0, 0xFF, 0xC0, 0x90, 0xC3, 0x90, 0x90];
            mapping.write(offset, &code);
            let scanner = InstructionScanner::default();
            let address = mapping.executable_address(offset);
            let scan = scanner.scan(&code, address).unwrap();
            let arena = crate::trampoline::TrampolineArena::allocate_near(address, 2).unwrap();
            // SAFETY: the dual aliases and arena are process-lifetime mappings.
            let hook = unsafe {
                InstalledHook::install_replacing_first_in_arena(
                    HookSite::new(
                        &scanner,
                        &scan,
                        &code,
                        address,
                        address,
                        mapping.writable_address(offset),
                    ),
                    replace_first_hook,
                    StalenessBudget::new(STALENESS_TICKS).unwrap(),
                    &arena,
                )
                .unwrap()
            };
            // SAFETY: fixture bytes implement extern C fn() -> u32.
            let function: unsafe extern "C" fn() -> u32 =
                unsafe { core::mem::transmute(address as usize) };

            assert_eq!(unsafe { function() }, 1);
            assert!(hook.activate().unwrap());
            assert_eq!(unsafe { function() }, 41);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
            assert!(hook.deactivate().unwrap());
            assert_eq!(unsafe { function() }, 1);
        }

        #[test]
        fn ptrace_stopped_hook_leaves_global_pc_publication_explicit() {
            let _guard = serial_guard();

            let mapping = DualMapping::new();
            let offset = 384;
            let code = [0x31, 0xC0, 0xFF, 0xC0, 0x90, 0xC3, 0x90, 0x90];
            mapping.write(offset, &code);
            let scanner = InstructionScanner::default();
            let address = mapping.executable_address(offset);
            let scan = scanner.scan(&code, address).unwrap();
            let arena = crate::trampoline::TrampolineArena::allocate_near(address, 2).unwrap();
            // SAFETY: both dual aliases and the arena live for the process, and
            // the test never activates the controller-owned breakpoint path.
            let hook = unsafe {
                InstalledHook::install_replacing_first_in_arena_quiescent_with_ptrace_stops(
                    HookSite::new(
                        &scanner,
                        &scan,
                        &code,
                        address,
                        address,
                        mapping.writable_address(offset),
                    ),
                    replace_first_hook,
                    &arena,
                )
                .unwrap()
            };
            let relocated = hook.trampoline().relocated_tail_address();
            assert!(
                !hook
                    .trampoline()
                    .program_counters_published
                    .load(Ordering::Acquire)
            );
            assert_eq!(translate_program_counter(relocated), None);

            hook.trampoline().publish_program_counter_mappings();
            assert!(
                hook.trampoline()
                    .program_counters_published
                    .load(Ordering::Acquire)
            );
            assert_eq!(translate_program_counter(relocated), Some(address + 2));
        }

        #[test]
        fn ptrace_stopped_hook_executes_on_owned_stack() {
            if let Some(control_fd) = std::env::var_os(PTRACE_CHILD_ENV) {
                let control_fd = control_fd.to_str().unwrap().parse::<libc::c_int>().unwrap();
                ptrace_stopped_child(control_fd);
            }

            let mut pipe = [-1; 2];
            // SAFETY: pipe names two writable descriptor slots.
            assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    PTRACE_CHILD_TEST,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(PTRACE_CHILD_ENV, pipe[1].to_string())
                .spawn()
                .unwrap();
            let mut child = PtraceChild::new(child);
            // SAFETY: pipe[0] is the parent's unique readable control-pipe
            // descriptor and is transferred to this guard.
            let control_reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
            // SAFETY: the parent no longer writes the control pipe.
            assert_eq!(unsafe { libc::close(pipe[1]) }, 0);
            let control = read_control_fd(control_reader.as_raw_fd());
            let tracee_tid = libc::pid_t::try_from(control.tracee_tid).unwrap();
            child.set_tracee_tid(tracee_tid);
            drop(control_reader);

            let initial_status = waitpid_event(tracee_tid, "initial SIGSTOP", true);
            assert!(libc::WIFSTOPPED(initial_status));
            assert_eq!(libc::WSTOPSIG(initial_status), libc::SIGSTOP);
            // SAFETY: the tracee is stopped and the option is an integer mask.
            assert_eq!(
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_SETOPTIONS,
                        tracee_tid,
                        core::ptr::null_mut::<libc::c_void>(),
                        libc::PTRACE_O_EXITKILL as usize as *mut libc::c_void,
                    )
                },
                0
            );
            ptrace_continue(tracee_tid);

            let entry_status = waitpid_event(tracee_tid, "entry stop", false);
            assert!(libc::WIFSTOPPED(entry_status));
            assert_eq!(libc::WSTOPSIG(entry_status), libc::SIGTRAP);
            let entry_registers = ptrace_getregs(tracee_tid);
            assert_eq!(entry_registers.rip, control.entry_rip);
            let application_rsp = entry_registers.rsp;
            let mut entry_xstate = ptrace_get_xstate(tracee_tid);
            entry_xstate[160..176].fill(0xa5);
            ptrace_set_xstate(tracee_tid, &mut entry_xstate);
            let entry_xstate = ptrace_get_xstate(tracee_tid);
            assert!(entry_xstate[160..176].iter().all(|byte| *byte == 0xa5));

            // SAFETY: owned_stack_top - 8 is mapped writable tracee memory and
            // POKEDATA carries the application RSP as one machine word.
            assert_eq!(
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_POKEDATA,
                        tracee_tid,
                        (control.owned_stack_top - 8) as usize as *mut libc::c_void,
                        application_rsp as usize as *mut libc::c_void,
                    )
                },
                0
            );
            let mut callback_registers = entry_registers;
            callback_registers.rsp = control.owned_stack_top;
            ptrace_setregs(tracee_tid, &callback_registers);
            assert_eq!(ptrace_getregs(tracee_tid).rsp, control.owned_stack_top);
            assert_eq!(ptrace_get_xstate(tracee_tid), entry_xstate);
            ptrace_continue(tracee_tid);

            let completion_status = waitpid_event(tracee_tid, "completion stop", false);
            assert!(libc::WIFSTOPPED(completion_status));
            assert_eq!(libc::WSTOPSIG(completion_status), libc::SIGTRAP);
            let mut completion_registers = ptrace_getregs(tracee_tid);
            assert_completion_registers(
                &entry_registers,
                &completion_registers,
                control.completion_rip,
                control.owned_stack_top,
            );
            assert_eq!(ptrace_get_xstate(tracee_tid), entry_xstate);

            let context_address = control.owned_stack_top - HOOK_CONTEXT_STACK_PREFIX_BYTES as u64;
            assert_eq!(
                ptrace_peek_u64(
                    tracee_tid,
                    context_address
                        + core::mem::offset_of!(HookContext, instruction_pointer) as u64,
                ),
                control.execute_address
            );
            assert_eq!(
                ptrace_peek_u64(
                    tracee_tid,
                    context_address + core::mem::offset_of!(HookContext, stack_pointer) as u64,
                ),
                application_rsp
            );
            let descriptor_address =
                context_address + core::mem::offset_of!(HookContext, saved_extended_state) as u64;
            let saved_address = ptrace_peek_u64(
                tracee_tid,
                descriptor_address
                    + core::mem::offset_of!(SavedExtendedStateDescriptor, address) as u64,
            );
            assert_eq!(
                ptrace_peek_u64(
                    tracee_tid,
                    descriptor_address
                        + core::mem::offset_of!(SavedExtendedStateDescriptor, len) as u64,
                ),
                control.saved_extended_state.len()
            );
            assert_eq!(
                ptrace_peek_u64(
                    tracee_tid,
                    descriptor_address
                        + core::mem::offset_of!(SavedExtendedStateDescriptor, mask) as u64,
                ),
                control.saved_extended_state.mask()
            );
            assert_eq!(
                ptrace_peek_u64(
                    tracee_tid,
                    descriptor_address
                        + core::mem::offset_of!(SavedExtendedStateDescriptor, format) as u64,
                ),
                control.saved_extended_state.format().raw()
            );
            let alignment = control
                .saved_extended_state
                .format()
                .required_alignment()
                .unwrap();
            assert_eq!(saved_address % alignment, 0);
            assert!(
                saved_address
                    >= control.owned_stack_top - u64::try_from(OWNED_STACK_BYTES).unwrap()
            );
            assert!(
                saved_address + control.saved_extended_state.len() <= context_address,
                "saved-state image escaped the authenticated owned-stack frame"
            );
            assert_eq!(
                ptrace_peek_u64(tracee_tid, saved_address + 160),
                u64::from_ne_bytes([0xa5; 8])
            );
            assert_eq!(
                ptrace_peek_u64(tracee_tid, saved_address + 168),
                u64::from_ne_bytes([0xa5; 8])
            );

            completion_registers.rsp = application_rsp;
            ptrace_setregs(tracee_tid, &completion_registers);
            assert_eq!(ptrace_getregs(tracee_tid).rsp, application_rsp);
            ptrace_continue(tracee_tid);

            let exit_status = waitpid_event(tracee_tid, "tracee exit", false);
            assert!(libc::WIFEXITED(exit_status));
            assert_eq!(libc::WEXITSTATUS(exit_status), 41);
            assert_eq!(child.wait_for_exit().code(), Some(41));
        }

        #[test]
        fn quiescent_arena_hook_patches_a_cache_line_straddler() {
            let _guard = serial_guard();
            CALLBACKS.store(0, Ordering::Relaxed);

            let mapping = DualMapping::new();
            let offset = 63;
            // xor eax,eax; inc eax; nop; ret; padding
            let code = [0x31, 0xC0, 0xFF, 0xC0, 0x90, 0xC3, 0x90, 0x90];
            mapping.write(offset, &code);
            let scanner = InstructionScanner::default();
            let address = mapping.executable_address(offset);
            let scan = scanner.scan(&code, address).unwrap();
            let arena = crate::trampoline::TrampolineArena::allocate_near(address, 2).unwrap();
            // SAFETY: the dual aliases and arena are process-lifetime mappings.
            let hook = unsafe {
                InstalledHook::install_replacing_first_in_arena_quiescent(
                    HookSite::new(
                        &scanner,
                        &scan,
                        &code,
                        address,
                        address,
                        mapping.writable_address(offset),
                    ),
                    replace_first_hook,
                    &arena,
                )
                .unwrap()
            };
            // SAFETY: fixture bytes implement extern C fn() -> u32.
            let function: unsafe extern "C" fn() -> u32 =
                unsafe { core::mem::transmute(address as usize) };

            assert_eq!(unsafe { function() }, 1);
            assert!(matches!(
                hook.activate(),
                Err(TrampolineError::Patch(
                    PatchError::QuiescentPublicationRequired
                ))
            ));
            // SAFETY: the test is single-threaded and runs no signal handlers.
            assert!(unsafe { hook.activate_quiescent() }.unwrap());
            assert_eq!(unsafe { function() }, 41);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
            assert_eq!(hook.handled_guard_traps(), 0);
            // SAFETY: the test is single-threaded and runs no signal handlers.
            assert!(unsafe { hook.deactivate_quiescent() }.unwrap());
            assert_eq!(unsafe { function() }, 1);
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
            use iced_x86::code_asm::CodeAssembler;
            use iced_x86::code_asm::rax;
            use iced_x86::code_asm::xmm0;
            use iced_x86::code_asm::ymm1;

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

// Runtime-control checks supplement the existing static emitter corpus.
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod observing_control_tests {
    use super::*;
    use crate::controls::{ControlledAction, ProbeControl};

    unsafe extern "C" fn observe(_: *mut HookContext) {}

    fn actions(base: u64) -> Vec<ControlledAction> {
        [0, 3, 6]
            .map(|offset| ControlledAction {
                logical_pc: base + offset,
                control: ProbeControl::new(observe, false),
            })
            .to_vec()
    }

    fn scan(base: u64) -> ScanResult {
        InstructionScanner::default()
            .scan(&[0x48, 0xff, 0xc0, 0x48, 0xff, 0xc0, 0xc3], base)
            .unwrap()
    }

    #[test]
    fn observing_control_plans_and_images_release_unused_references() {
        let base = 0x10_0000;
        let scan = scan(base);
        let actions = actions(base);
        let weak: Vec<_> = actions
            .iter()
            .map(|action| action.control.downgrade())
            .collect();
        let plan =
            TrampolinePlan::from_controlled_actions(&scan, base, base + 7, &actions).unwrap();
        assert!(weak.iter().all(|control| control.strong_count() == 2));
        let image = plan.emit_at(base + 0x20_0000).unwrap();
        assert_eq!(image.controls().len(), 3);
        assert!(weak.iter().all(|control| control.strong_count() == 3));
        drop(actions);
        drop(plan);
        assert!(weak.iter().all(|control| control.strong_count() == 1));
        drop(image);
        assert!(weak.iter().all(|control| control.upgrade().is_none()));
    }

    #[test]
    fn observing_control_refusals_leave_no_hidden_control_owner() {
        let base = 0x10_0000;
        let scan = scan(base);
        let actions = actions(base);
        let weak: Vec<_> = actions
            .iter()
            .map(|action| action.control.downgrade())
            .collect();
        for invalid in [
            vec![],
            vec![actions[1].clone(), actions[0].clone()],
            vec![actions[0].clone(), actions[0].clone()],
            vec![ControlledAction {
                logical_pc: base + 1,
                control: actions[0].control.clone(),
            }],
            vec![
                actions[0].clone(),
                ControlledAction {
                    logical_pc: base + 3,
                    control: actions[0].control.clone(),
                },
            ],
        ] {
            assert!(
                TrampolinePlan::from_controlled_actions(&scan, base, base + 7, &invalid).is_err()
            );
        }
        assert!(weak.iter().all(|control| control.strong_count() == 1));
        let plan =
            TrampolinePlan::from_controlled_actions(&scan, base, base + 7, &actions).unwrap();
        assert!(plan.emit_at(u64::MAX - 8).is_err());
        assert!(weak.iter().all(|control| control.strong_count() == 2));
        drop(plan);
        drop(actions);
        assert!(weak.iter().all(|control| control.upgrade().is_none()));
    }

    #[test]
    fn observing_control_changes_leave_all_emitted_bytes_and_maps_identical() {
        let base = 0x10_0000;
        let scan = scan(base);
        let actions = actions(base);
        let plan =
            TrampolinePlan::from_controlled_actions(&scan, base, base + 7, &actions).unwrap();
        let static_plan = TrampolinePlan::from_actions(
            &scan,
            base,
            base + 7,
            &[
                (base, observe, false),
                (base + 3, observe, false),
                (base + 6, observe, false),
            ],
        )
        .unwrap();
        let image = plan.emit_at(base + 0x20_0000).unwrap();
        let static_image = static_plan.emit_at(base + 0x20_0000).unwrap();
        assert!(static_image.controls().is_empty());
        assert_eq!(image.entry_routes().len(), 3);
        assert_eq!(
            image.instruction_boundaries().len(),
            3,
            "all original instructions remain"
        );
        for subset in 0..8 {
            for (index, action) in actions.iter().enumerate() {
                action.control.set_enabled(subset & (1 << index) != 0);
            }
            assert_eq!(plan.emit_at(image.address()).unwrap(), image);
            assert_eq!(
                static_plan.emit_at(static_image.address()).unwrap(),
                static_image
            );
            assert_eq!(scan.snapshot(), [0x48, 0xff, 0xc0, 0x48, 0xff, 0xc0, 0xc3]);
        }
    }

    #[test]
    fn observing_control_staged_drop_unmaps_before_releasing_last_owners() {
        super::run_staged_drop_test(
            "trampoline::observing_control_tests::observing_control_staged_drop_unmaps_before_releasing_last_owners",
            observing_control_staged_drop_unmaps_before_releasing_last_owners_body,
        );
    }

    fn observing_control_staged_drop_unmaps_before_releasing_last_owners_body() {
        let base = observe as *const () as usize as u64;
        let scan = scan(base);
        let actions = actions(base);
        let weak: Vec<_> = actions
            .iter()
            .map(|action| action.control.downgrade())
            .collect();
        let plan =
            TrampolinePlan::from_controlled_actions(&scan, base, base + 7, &actions).unwrap();
        let mapping = PendingMapping::allocate_near(base).unwrap();
        let address = mapping.executable as usize as u64;
        let image = plan.emit_at(address).unwrap();
        let staged = PendingExecutableTrampoline {
            trampoline: Some(mapping.publish_at(&image, 0).unwrap()),
        };
        drop(image);
        drop(plan);
        drop(actions);
        assert!(weak.iter().all(|control| control.strong_count() == 1));
        drop(staged);
        assert!(weak.iter().all(|control| control.upgrade().is_none()));
        // Exact replacement reservation proves the retired staging alias is gone.
        let _reservation = PendingMapping::allocate_exact(address as usize, 4096, address).unwrap();
    }

    #[test]
    fn observing_control_grouped_rollback_releases_its_clones() {
        use crate::grouping::{GroupingBudget, GroupingPlan};
        let base = 0x10_0000;
        let scan = scan(base);
        let actions = actions(base);
        let weak: Vec<_> = actions
            .iter()
            .map(|action| action.control.downgrade())
            .collect();
        let plan =
            TrampolinePlan::from_controlled_actions(&scan, base, base + 7, &actions).unwrap();
        // This dedicated finite test address is unrelated to the live source;
        // MAP_FIXED_NOREPLACE must fail rather than replace any existing VMA.
        let address = 0x57c0_0000_0100;
        let image = plan.emit_at(address).unwrap();
        let grouping = GroupingPlan::new(vec![image], GroupingBudget::default()).unwrap();
        let staged = grouping.stage().unwrap();
        drop(grouping);
        drop(plan);
        drop(actions);
        assert!(weak.iter().all(|control| control.strong_count() == 1));
        drop(staged);
        assert!(weak.iter().all(|control| control.upgrade().is_none()));
        let _reservation =
            PendingMapping::allocate_exact((address & !4095) as usize, 4096, address).unwrap();
    }

    #[test]
    fn observing_control_executable_drop_keeps_code_dependencies_alive() {
        let base = observe as *const () as usize as u64;
        let scan = scan(base);
        let actions = actions(base);
        let weak: Vec<_> = actions
            .iter()
            .map(|action| action.control.downgrade())
            .collect();
        let plan =
            TrampolinePlan::from_controlled_actions(&scan, base, base + 7, &actions).unwrap();
        let executable = ExecutableTrampoline::allocate(&plan).unwrap();
        drop(plan);
        drop(actions);
        assert!(weak.iter().all(|control| control.strong_count() == 1));
        drop(executable);
        assert!(
            weak.iter().all(|control| control.strong_count() == 1),
            "process-lifetime code retains its embedded control pointers"
        );
    }

    #[test]
    fn observing_control_arena_refusal_preserves_slots_bytes_and_static_support() {
        let base = observe as *const () as usize as u64;
        let scan = scan(base);
        let actions = actions(base);
        let weak: Vec<_> = actions
            .iter()
            .map(|action| action.control.downgrade())
            .collect();
        let plan =
            TrampolinePlan::from_controlled_actions(&scan, base, base + 7, &actions).unwrap();
        let arena = TrampolineArena::allocate_near(base, 1).unwrap();
        // SAFETY: this private fixture owns a fresh readable RX arena mapping.
        let before = unsafe { core::slice::from_raw_parts(arena.executable, arena.len) }.to_vec();
        assert!(matches!(
            arena.allocate(&plan),
            Err(TrampolineError::ControlledArenaUnsupported)
        ));
        // SAFETY: successful arena construction initialized its reservation cursor.
        assert_eq!(unsafe { (*arena.next).load(Ordering::Acquire) }, 0);
        // SAFETY: no allocation or writer has touched the same private mapping.
        assert_eq!(
            unsafe { core::slice::from_raw_parts(arena.executable, arena.len) },
            before
        );
        drop(plan);
        drop(actions);
        assert!(weak.iter().all(|control| control.upgrade().is_none()));
        let static_plan =
            TrampolinePlan::from_actions(&scan, base, base + 7, &[(base, observe, false)]).unwrap();
        let executable = arena.allocate(&static_plan).unwrap();
        assert_eq!(executable.address(), arena.executable as usize as u64);
        assert!(matches!(
            arena.allocate(&static_plan),
            Err(TrampolineError::ArenaFull)
        ));
    }

    #[test]
    fn observing_control_native_subsets_and_retained_dispatch_after_handle_drop() {
        const CHILD: &str = "LITEINST2_OBSERVING_CONTROL_NATIVE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            use std::os::unix::process::CommandExt;
            use std::time::{Duration, Instant};
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args([
                "--exact",
                "trampoline::observing_control_tests::observing_control_native_subsets_and_retained_dispatch_after_handle_drop",
                "--test-threads=1",
                "--nocapture",
            ]).env(CHILD, "1");
            // SAFETY: only async-signal-safe resource calls run before exec.
            unsafe {
                command.pre_exec(|| {
                    for (resource, limit) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_CPU, 5)] {
                        let bound = libc::rlimit {
                            rlim_cur: limit,
                            rlim_max: limit,
                        };
                        if libc::setrlimit(resource, &bound) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
            let mut child = command.spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "controlled native child failed: {status}");
                    return;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("controlled native child exceeded ten seconds");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        static EVENTS: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
        unsafe extern "C" fn first(_: *mut HookContext) {
            EVENTS[0].fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn second(_: *mut HookContext) {
            EVENTS[1].fetch_add(1, Ordering::Relaxed);
        }
        unsafe extern "C" fn third(_: *mut HookContext) {
            EVENTS[2].fetch_add(1, Ordering::Relaxed);
        }
        fn invoke(address: u64) -> u64 {
            let mut value = 40_u64;
            // SAFETY: this bounded child executes a fully initialized private
            // image containing two INC RAX instructions and RET. Each callback
            // has the complete saved frame and the executable owner retains its
            // controls. No source patch or external application entry exists.
            unsafe {
                core::arch::asm!("call r11", in("r11") address,
                    inlateout("rax") value, clobber_abi("C"));
            }
            value
        }
        let base = first as *const () as usize as u64;
        let scan = scan(base);
        let actions: Vec<_> = [first as HookCallback, second, third]
            .into_iter()
            .enumerate()
            .map(|(index, callback)| ControlledAction {
                logical_pc: base + (index * 3) as u64,
                control: ProbeControl::new(callback, false),
            })
            .collect();
        let weak: Vec<_> = actions
            .iter()
            .map(|action| action.control.downgrade())
            .collect();
        let plan =
            TrampolinePlan::from_controlled_actions(&scan, base, base + 7, &actions).unwrap();
        let executable = ExecutableTrampoline::allocate(&plan).unwrap();
        let image = plan.emit_at(executable.address()).unwrap();
        let entries: Vec<_> = image.entry_routes().iter().map(|entry| entry.1).collect();
        let address = executable.address();
        let original_bytes = image.bytes().to_vec();
        for subset in 0..8 {
            for (index, action) in actions.iter().enumerate() {
                action.control.set_enabled(subset & (1 << index) != 0);
            }
            for (entry_index, &entry) in entries.iter().enumerate() {
                for event in &EVENTS {
                    event.store(0, Ordering::Relaxed);
                }
                assert_eq!(invoke(entry), 42 - entry_index as u64);
                for (index, event) in EVENTS.iter().enumerate() {
                    assert_eq!(
                        event.load(Ordering::Relaxed),
                        usize::from(index >= entry_index && subset & (1 << index) != 0)
                    );
                }
            }
            // SAFETY: the executable mapping remains live and immutable.
            assert_eq!(
                unsafe { core::slice::from_raw_parts(address as *const u8, original_bytes.len()) },
                original_bytes
            );
        }
        for action in &actions {
            action.control.set_enabled(true);
        }
        drop(actions);
        drop(plan);
        drop(image);
        drop(executable);
        assert!(weak.iter().all(|control| control.strong_count() == 1));
        for (entry_index, &entry) in entries.iter().enumerate() {
            for event in &EVENTS {
                event.store(0, Ordering::Relaxed);
            }
            assert_eq!(invoke(entry), 42 - entry_index as u64);
            for (index, event) in EVENTS.iter().enumerate() {
                assert_eq!(
                    event.load(Ordering::Relaxed),
                    usize::from(index >= entry_index)
                );
            }
        }
        // SAFETY: process-lifetime code and controls survive all owner handles.
        assert_eq!(
            unsafe { core::slice::from_raw_parts(address as *const u8, original_bytes.len()) },
            original_bytes
        );
    }
}
