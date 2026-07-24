//! Atomic publication of live x86-64 instruction patches.
//!
//! A patch is planned without touching executable memory, then bound to a
//! process-lifetime writable alias of the executable mapping. Cross-line words
//! use WordPatch++: atomically guard every reachable front-line instruction
//! head, wait for bounded instruction-fetch staleness, publish the aligned back
//! word, wait again, and finally publish the aligned front word.
//!
//! Intel does not architecturally guarantee instruction-fetch coherence for
//! this protocol. Callers must provide a staleness budget calibrated for every
//! supported machine.

use core::fmt;
use core::num::NonZeroU64;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU64, Ordering, compiler_fence};

use crate::cache_line::CacheLineSize;
use crate::scanner::{InstructionScanner, ScanError, ScanResult};
use crate::trap::{TrapError, TrapSite};

/// x86 near-jump opcode used to redirect execution to a trampoline.
pub const NEAR_JUMP_OPCODE: u8 = 0xE9;

/// Trap opcode used to guard instruction heads during cross-line publication.
pub const BREAKPOINT_OPCODE: u8 = 0xCC;

/// Number of bytes in an x86 near jump with a signed 32-bit displacement.
pub const NEAR_JUMP_BYTES: usize = 5;

/// Number of bytes published by the generic x86-64 WordPatch operation.
pub const WORD_PATCH_BYTES: usize = 8;

/// Publication strategy required for an eight-byte patch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchStrategy {
    /// The complete word is contained in one cache line.
    AtomicWord,
    /// The word is split and requires guarded front/back publication.
    GuardedSplit {
        /// Bytes in the cache line containing the patch start.
        front_len: usize,
        /// Bytes in the following cache line.
        back_len: usize,
    },
}

/// Classifies the publication strategy for an eight-byte patch at `address`.
pub fn classify_word_patch(address: usize, cache_line: CacheLineSize) -> PatchStrategy {
    match cache_line.split_offset(address, WORD_PATCH_BYTES) {
        Some(front_len) => PatchStrategy::GuardedSplit {
            front_len,
            back_len: WORD_PATCH_BYTES - front_len,
        },
        None => PatchStrategy::AtomicWord,
    }
}

/// Calibrated minimum delay between WordPatch++ publication phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StalenessBudget(NonZeroU64);

impl StalenessBudget {
    /// Creates a non-zero delay measured in timestamp-counter ticks.
    pub const fn new(cycles: u64) -> Option<Self> {
        match NonZeroU64::new(cycles) {
            Some(cycles) => Some(Self(cycles)),
            None => None,
        }
    }

    /// Returns the configured timestamp-counter ticks.
    pub const fn cycles(self) -> u64 {
        self.0.get()
    }

    #[cfg(target_arch = "x86_64")]
    fn wait(self) {
        use core::arch::x86_64::{_mm_lfence, _rdtsc};
        use core::hint::spin_loop;

        compiler_fence(Ordering::SeqCst);
        // SAFETY: LFENCE serializes the timestamp read against prior stores.
        unsafe { _mm_lfence() };
        // SAFETY: RDTSC is available in x86-64 mode.
        let start = unsafe { _rdtsc() };
        loop {
            // SAFETY: serialize each timestamp sample so the observed delay is
            // not shortened by out-of-order execution.
            unsafe { _mm_lfence() };
            // SAFETY: RDTSC is available in x86-64 mode.
            let elapsed = unsafe { _rdtsc() }.wrapping_sub(start);
            if elapsed >= self.cycles() {
                break;
            }
            spin_loop();
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Errors returned while planning, binding, or publishing a jump patch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchError {
    /// The requested address is not an instruction head in the scan.
    SiteNotFound {
        /// Requested executable address.
        address: u64,
    },
    /// The supplied code region cannot be completely decoded.
    InvalidCodeRegion {
        /// Scanner failure that made planning unsafe.
        source: ScanError,
    },
    /// The scan and supplied code region disagree about instruction heads.
    RegionMismatch {
        /// Requested executable address.
        address: u64,
    },
    /// The first instruction cannot contain a five-byte direct jump.
    InstructionTooShort {
        /// Instruction address.
        address: u64,
        /// Decoded instruction length.
        instruction_len: usize,
    },
    /// The region does not contain the complete eight-byte patch window.
    PatchWindowOutOfRange {
        /// Instruction address.
        address: u64,
    },
    /// The trampoline cannot be reached by a signed rel32 jump.
    TargetOutOfRange {
        /// Instruction address.
        address: u64,
        /// Requested trampoline address.
        target: u64,
    },
    /// An address cannot be represented by the host pointer width.
    AddressNotRepresentable {
        /// Address that failed conversion.
        address: u64,
    },
    /// Cache-line geometry cannot support aligned atomic front/back words.
    UnsupportedCacheLineSize {
        /// Configured cache-line size.
        bytes: usize,
    },
    /// An instruction head already contains the temporary breakpoint opcode.
    GuardByteConflict {
        /// Address of the conflicting instruction head.
        address: u64,
    },
    /// The writable alias is null.
    NullWritableAddress,
    /// Writable and executable aliases have different cache-line offsets.
    AliasAlignmentMismatch,
    /// Address arithmetic overflowed while reserving atomic write words.
    AddressRangeOverflow,
    /// Another patch owns an overlapping atomic write envelope.
    OverlappingPatchSite,
    /// Another writer is already publishing at this site.
    Contended,
    /// Live code does not match the state expected by apply or revert.
    ExpectedBytesMismatch,
    /// Installing the SIGTRAP guard handler failed.
    SignalHandlerInstall {
        /// Operating-system error number.
        errno: i32,
    },
    /// Live patching is unavailable on this target.
    UnsupportedPlatform,
}

impl fmt::Display for PatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SiteNotFound { address } => {
                write!(formatter, "no scanned instruction starts at {address:#x}")
            }
            Self::InvalidCodeRegion { source } => {
                write!(formatter, "invalid code region: {source}")
            }
            Self::RegionMismatch { address } => {
                write!(formatter, "scan and code region disagree at {address:#x}")
            }
            Self::InstructionTooShort {
                address,
                instruction_len,
            } => write!(
                formatter,
                "instruction at {address:#x} is {instruction_len} bytes; a direct jump needs {NEAR_JUMP_BYTES}"
            ),
            Self::PatchWindowOutOfRange { address } => {
                write!(
                    formatter,
                    "eight-byte patch window at {address:#x} is outside the region"
                )
            }
            Self::TargetOutOfRange { address, target } => write!(
                formatter,
                "trampoline {target:#x} is outside rel32 reach from {address:#x}"
            ),
            Self::AddressNotRepresentable { address } => {
                write!(formatter, "address {address:#x} is not representable")
            }
            Self::UnsupportedCacheLineSize { bytes } => write!(
                formatter,
                "{bytes}-byte cache lines do not align eight-byte atomic words"
            ),
            Self::GuardByteConflict { address } => write!(
                formatter,
                "instruction head at {address:#x} already contains the guard opcode"
            ),
            Self::NullWritableAddress => formatter.write_str("writable patch address is null"),
            Self::AliasAlignmentMismatch => {
                formatter.write_str("writable and executable aliases have different line offsets")
            }
            Self::AddressRangeOverflow => formatter.write_str("patch address range overflowed"),
            Self::OverlappingPatchSite => {
                formatter.write_str("patch atomic-write envelope overlaps another registered site")
            }
            Self::Contended => formatter.write_str("another writer is patching this site"),
            Self::ExpectedBytesMismatch => {
                formatter.write_str("live code does not match the expected patch state")
            }
            Self::SignalHandlerInstall { errno } => {
                write!(
                    formatter,
                    "failed to install SIGTRAP handler: errno {errno}"
                )
            }
            Self::UnsupportedPlatform => {
                formatter.write_str("live patching requires Linux on x86-64")
            }
        }
    }
}

impl std::error::Error for PatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCodeRegion { source } => Some(source),
            _ => None,
        }
    }
}

/// Immutable plan for redirecting one instruction to a trampoline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JumpPatchPlan {
    execute_address: u64,
    target_address: u64,
    original: [u8; WORD_PATCH_BYTES],
    replacement: [u8; WORD_PATCH_BYTES],
    strategy: PatchStrategy,
    cache_line: CacheLineSize,
    guard_mask: u8,
}

impl JumpPatchPlan {
    /// Plans a direct jump using an M1 scan of `code`.
    ///
    /// The first instruction must be at least five bytes. This avoids
    /// overwriting a later instruction head with unconstrained displacement
    /// bytes; shorter instructions require a future punning/relocation plan.
    pub fn from_scan(
        scanner: &InstructionScanner,
        scan: &ScanResult,
        code: &[u8],
        region_base: u64,
        execute_address: u64,
        target_address: u64,
    ) -> Result<Self, PatchError> {
        let verified_scan = scanner
            .scan(code, region_base)
            .map_err(|source| PatchError::InvalidCodeRegion { source })?;
        if verified_scan.sites() != scan.sites() {
            return Err(PatchError::RegionMismatch {
                address: execute_address,
            });
        }

        let site = scan.site(execute_address).ok_or(PatchError::SiteNotFound {
            address: execute_address,
        })?;
        let relative =
            execute_address
                .checked_sub(region_base)
                .ok_or(PatchError::RegionMismatch {
                    address: execute_address,
                })?;
        let offset = usize::try_from(relative).map_err(|_| PatchError::RegionMismatch {
            address: execute_address,
        })?;
        if offset != site.offset() {
            return Err(PatchError::RegionMismatch {
                address: execute_address,
            });
        }
        if site.instruction_len() < NEAR_JUMP_BYTES {
            return Err(PatchError::InstructionTooShort {
                address: execute_address,
                instruction_len: site.instruction_len(),
            });
        }

        let patch_end =
            offset
                .checked_add(WORD_PATCH_BYTES)
                .ok_or(PatchError::PatchWindowOutOfRange {
                    address: execute_address,
                })?;
        let patch_bytes = code
            .get(offset..patch_end)
            .ok_or(PatchError::PatchWindowOutOfRange {
                address: execute_address,
            })?;
        let original: [u8; WORD_PATCH_BYTES] =
            patch_bytes
                .try_into()
                .map_err(|_| PatchError::PatchWindowOutOfRange {
                    address: execute_address,
                })?;

        let next_ip = execute_address.checked_add(NEAR_JUMP_BYTES as u64).ok_or(
            PatchError::TargetOutOfRange {
                address: execute_address,
                target: target_address,
            },
        )?;
        let displacement = i128::from(target_address) - i128::from(next_ip);
        let displacement =
            i32::try_from(displacement).map_err(|_| PatchError::TargetOutOfRange {
                address: execute_address,
                target: target_address,
            })?;

        let native_address =
            usize::try_from(execute_address).map_err(|_| PatchError::AddressNotRepresentable {
                address: execute_address,
            })?;
        let cache_line = scanner.cache_line_size();
        let strategy = classify_word_patch(native_address, cache_line);
        if matches!(strategy, PatchStrategy::GuardedSplit { .. })
            && (cache_line.get() < WORD_PATCH_BYTES || cache_line.get() % WORD_PATCH_BYTES != 0)
        {
            return Err(PatchError::UnsupportedCacheLineSize {
                bytes: cache_line.get(),
            });
        }

        let mut replacement = original;
        replacement[0] = NEAR_JUMP_OPCODE;
        replacement[1..NEAR_JUMP_BYTES].copy_from_slice(&displacement.to_le_bytes());

        let guard_mask = match strategy {
            PatchStrategy::AtomicWord => 0,
            PatchStrategy::GuardedSplit { front_len, .. } => {
                let boundary = execute_address
                    .checked_add(front_len as u64)
                    .ok_or(PatchError::AddressRangeOverflow)?;
                let mut mask = 0_u8;
                for (&address, _) in scan.sites().range(execute_address..boundary) {
                    let relative = address - execute_address;
                    let relative =
                        usize::try_from(relative).map_err(|_| PatchError::RegionMismatch {
                            address: execute_address,
                        })?;
                    if relative < front_len {
                        if original[relative] == BREAKPOINT_OPCODE
                            || replacement[relative] == BREAKPOINT_OPCODE
                        {
                            return Err(PatchError::GuardByteConflict { address });
                        }
                        mask |= 1 << relative;
                    }
                }
                if mask & 1 == 0 {
                    return Err(PatchError::RegionMismatch {
                        address: execute_address,
                    });
                }
                mask
            }
        };

        Ok(Self {
            execute_address,
            target_address,
            original,
            replacement,
            strategy,
            cache_line,
            guard_mask,
        })
    }

    /// Returns the executable patch address.
    pub const fn execute_address(&self) -> u64 {
        self.execute_address
    }

    /// Returns the trampoline target address.
    pub const fn target_address(&self) -> u64 {
        self.target_address
    }

    /// Returns the original eight-byte window.
    pub const fn original_bytes(&self) -> [u8; WORD_PATCH_BYTES] {
        self.original
    }

    /// Returns the replacement eight-byte window.
    pub const fn replacement_bytes(&self) -> [u8; WORD_PATCH_BYTES] {
        self.replacement
    }

    /// Returns the required publication strategy.
    pub const fn strategy(&self) -> PatchStrategy {
        self.strategy
    }

    /// Iterates over instruction-head offsets guarded during publication.
    pub fn guarded_instruction_offsets(&self) -> impl Iterator<Item = usize> + '_ {
        (0..WORD_PATCH_BYTES).filter(|offset| self.guard_mask & (1 << offset) != 0)
    }
}

/// A jump plan bound to writable and executable aliases of live code.
///
/// Trap registration intentionally lasts for the process lifetime. Therefore
/// the executable address must not be unmapped, reused, or used for unrelated
/// breakpoints after binding.
pub struct LiveJumpPatch {
    plan: JumpPatchPlan,
    writable_address: *mut u8,
    staleness: StalenessBudget,
    trap_site: &'static TrapSite,
}

impl LiveJumpPatch {
    /// Binds a plan to a writable alias of its executable mapping.
    ///
    /// # Safety
    ///
    /// `writable_address` must remain valid for the complete atomic write
    /// envelope for the process lifetime. It must alias the physical bytes at
    /// `plan.execute_address()`, have the same cache-line offset, and permit
    /// concurrent atomic stores. The executable alias must remain mapped and
    /// executable for the process lifetime.
    pub unsafe fn bind(
        plan: JumpPatchPlan,
        writable_address: *mut u8,
        staleness: StalenessBudget,
    ) -> Result<Self, PatchError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (plan, writable_address, staleness);
            return Err(PatchError::UnsupportedPlatform);
        }

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            if writable_address.is_null() {
                return Err(PatchError::NullWritableAddress);
            }
            let execute_address = usize::try_from(plan.execute_address).map_err(|_| {
                PatchError::AddressNotRepresentable {
                    address: plan.execute_address,
                }
            })?;
            let writable = writable_address as usize;
            let line_size = plan.cache_line.get();
            if execute_address % line_size != writable % line_size {
                return Err(PatchError::AliasAlignmentMismatch);
            }

            let (reservation_start, reservation_end) = match plan.strategy {
                PatchStrategy::AtomicWord => {
                    let end = execute_address
                        .checked_add(WORD_PATCH_BYTES)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    (execute_address, end)
                }
                PatchStrategy::GuardedSplit { front_len, .. } => {
                    let boundary = execute_address
                        .checked_add(front_len)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    let start = boundary
                        .checked_sub(WORD_PATCH_BYTES)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    let end = boundary
                        .checked_add(WORD_PATCH_BYTES)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    let writable_boundary = writable
                        .checked_add(front_len)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    if writable_boundary % WORD_PATCH_BYTES != 0 {
                        return Err(PatchError::AliasAlignmentMismatch);
                    }
                    (start, end)
                }
            };

            let trap_site = crate::trap::register(
                execute_address,
                reservation_start,
                reservation_end,
                plan.guard_mask,
            )
            .map_err(map_trap_error)?;

            Ok(Self {
                plan,
                writable_address,
                staleness,
                trap_site,
            })
        }
    }

    /// Returns the immutable patch plan.
    pub const fn plan(&self) -> &JumpPatchPlan {
        &self.plan
    }

    /// Returns the number of guard traps handled for this site.
    pub fn handled_guard_traps(&self) -> u64 {
        self.trap_site.handled_traps()
    }

    /// Publishes the trampoline redirect.
    ///
    /// # Safety
    ///
    /// The mappings supplied to bind must still satisfy its safety contract,
    /// and no unregistered writer may modify the atomic write envelope.
    pub unsafe fn apply(&self) -> Result<(), PatchError> {
        // SAFETY: upheld by the caller and bind contract.
        unsafe { self.publish(self.plan.original, self.plan.replacement) }
    }

    /// Restores the original instruction bytes.
    ///
    /// # Safety
    ///
    /// The mappings supplied to bind must still satisfy its safety contract,
    /// and no unregistered writer may modify the atomic write envelope.
    pub unsafe fn revert(&self) -> Result<(), PatchError> {
        // SAFETY: upheld by the caller and bind contract.
        unsafe { self.publish(self.plan.replacement, self.plan.original) }
    }

    unsafe fn publish(
        &self,
        expected: [u8; WORD_PATCH_BYTES],
        replacement: [u8; WORD_PATCH_BYTES],
    ) -> Result<(), PatchError> {
        self.trap_site.begin().map_err(map_trap_error)?;

        let result = match self.plan.strategy {
            PatchStrategy::AtomicWord => {
                // SAFETY: bind validated the complete writable patch window.
                unsafe { publish_single_line(self.writable_address, expected, replacement) }
            }
            PatchStrategy::GuardedSplit {
                front_len,
                back_len,
            } => {
                // SAFETY: bind validated both aligned writable words.
                unsafe {
                    publish_cross_line(
                        self.writable_address,
                        front_len,
                        back_len,
                        self.plan.guard_mask,
                        expected,
                        replacement,
                        self.staleness,
                    )
                }
            }
        };

        self.trap_site.finish();
        result
    }
}

fn map_trap_error(error: TrapError) -> PatchError {
    match error {
        TrapError::Contended => PatchError::Contended,
        TrapError::Overlap => PatchError::OverlappingPatchSite,
        TrapError::Install(errno) => PatchError::SignalHandlerInstall { errno },
        TrapError::Unsupported => PatchError::UnsupportedPlatform,
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn publish_single_line(
    address: *mut u8,
    expected: [u8; WORD_PATCH_BYTES],
    replacement: [u8; WORD_PATCH_BYTES],
) -> Result<(), PatchError> {
    let expected = u64::from_le_bytes(expected);
    // SAFETY: caller guarantees a readable eight-byte window.
    let current = unsafe { load_unaligned_word(address.cast_const()) };
    if current != expected {
        return Err(PatchError::ExpectedBytesMismatch);
    }

    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller guarantees a writable, single-cache-line window.
    unsafe { store_unaligned_word(address, u64::from_le_bytes(replacement)) };
    compiler_fence(Ordering::SeqCst);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
unsafe fn publish_cross_line(
    address: *mut u8,
    front_len: usize,
    back_len: usize,
    guard_mask: u8,
    expected: [u8; WORD_PATCH_BYTES],
    replacement: [u8; WORD_PATCH_BYTES],
    staleness: StalenessBudget,
) -> Result<(), PatchError> {
    // SAFETY: bind validated the aligned words surrounding the boundary.
    let boundary = unsafe { address.add(front_len) };
    // SAFETY: front_len is at most seven for a crossing eight-byte window.
    let front_ptr = unsafe { boundary.sub(WORD_PATCH_BYTES) }.cast::<AtomicU64>();
    let back_ptr = boundary.cast::<AtomicU64>();

    // SAFETY: pointers are aligned, live AtomicU64 storage for this protocol.
    let front = unsafe { &*front_ptr };
    // SAFETY: pointers are aligned, live AtomicU64 storage for this protocol.
    let back = unsafe { &*back_ptr };

    let current_front = front.load(Ordering::SeqCst);
    let current_back = back.load(Ordering::SeqCst);
    let front_offset = WORD_PATCH_BYTES - front_len;

    let current_front_bytes = current_front.to_le_bytes();
    let current_back_bytes = current_back.to_le_bytes();
    let mut current = [0_u8; WORD_PATCH_BYTES];
    current[..front_len].copy_from_slice(&current_front_bytes[front_offset..]);
    current[front_len..].copy_from_slice(&current_back_bytes[..back_len]);
    if current != expected {
        return Err(PatchError::ExpectedBytesMismatch);
    }

    let mut new_front_bytes = current_front_bytes;
    new_front_bytes[front_offset..].copy_from_slice(&replacement[..front_len]);
    let new_front = u64::from_le_bytes(new_front_bytes);

    let mut new_back_bytes = current_back_bytes;
    new_back_bytes[..back_len].copy_from_slice(&replacement[front_len..]);
    let new_back = u64::from_le_bytes(new_back_bytes);

    let mut guarded_front_bytes = current_front_bytes;
    for offset in 0..front_len {
        if guard_mask & (1 << offset) != 0 {
            guarded_front_bytes[front_offset + offset] = BREAKPOINT_OPCODE;
        }
    }
    let guarded_front = u64::from_le_bytes(guarded_front_bytes);

    if front
        .compare_exchange(
            current_front,
            guarded_front,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_err()
    {
        return Err(PatchError::Contended);
    }

    staleness.wait();
    back.store(new_back, Ordering::SeqCst);
    staleness.wait();
    front.store(new_front, Ordering::SeqCst);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
unsafe fn load_unaligned_word(address: *const u8) -> u64 {
    let value: u64;
    // SAFETY: caller provides a readable eight-byte window. One MOV is required
    // so the compiler cannot split the load.
    unsafe {
        core::arch::asm!(
            "mov {value}, qword ptr [{address}]",
            value = out(reg) value,
            address = in(reg) address,
            options(nostack, preserves_flags, readonly),
        );
    }
    value
}

#[cfg(target_arch = "x86_64")]
unsafe fn store_unaligned_word(address: *mut u8, value: u64) {
    // SAFETY: caller provides a writable eight-byte window wholly within one
    // cache line. One MOV is required so the compiler cannot split the store.
    unsafe {
        core::arch::asm!(
            "mov qword ptr [{address}], {value}",
            address = in(reg) address,
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn publish_single_line(
    _address: *mut u8,
    _expected: [u8; WORD_PATCH_BYTES],
    _replacement: [u8; WORD_PATCH_BYTES],
) -> Result<(), PatchError> {
    Err(PatchError::UnsupportedPlatform)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn publish_cross_line(
    _address: *mut u8,
    _front_len: usize,
    _back_len: usize,
    _guard_mask: u8,
    _expected: [u8; WORD_PATCH_BYTES],
    _replacement: [u8; WORD_PATCH_BYTES],
    _staleness: StalenessBudget,
) -> Result<(), PatchError> {
    Err(PatchError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::{JumpPatchPlan, NEAR_JUMP_OPCODE, PatchError, PatchStrategy, classify_word_patch};
    use crate::cache_line::CacheLineSize;
    use crate::scanner::InstructionScanner;

    const LINE: CacheLineSize = CacheLineSize::new(64).unwrap();

    fn plan_for(code: &[u8], base: u64, target: u64) -> Result<JumpPatchPlan, PatchError> {
        let scanner = InstructionScanner::default();
        let scan = scanner
            .scan(code, base)
            .expect("test fixture must decode completely");
        JumpPatchPlan::from_scan(&scanner, &scan, code, base, base, target)
    }

    #[test]
    fn classifies_all_word_splits() {
        for front_len in 1..8 {
            let address = 64 - front_len;
            assert_eq!(
                classify_word_patch(address, LINE),
                PatchStrategy::GuardedSplit {
                    front_len,
                    back_len: 8 - front_len,
                }
            );
        }
    }

    #[test]
    fn word_ending_at_boundary_is_single_line() {
        assert_eq!(classify_word_patch(56, LINE), PatchStrategy::AtomicWord);
    }

    #[test]
    fn plans_jump_for_immediate_instruction_crossing_a_line() {
        let code = [0xB8, 1, 0, 0, 0, 0xC3, 0x90, 0x90];
        let plan = plan_for(&code, 60, 0x1000).unwrap();

        assert_eq!(
            plan.strategy(),
            PatchStrategy::GuardedSplit {
                front_len: 4,
                back_len: 4,
            }
        );
        assert_eq!(plan.replacement_bytes()[0], NEAR_JUMP_OPCODE);
        assert_eq!(
            plan.guarded_instruction_offsets().collect::<Vec<_>>(),
            vec![0]
        );
    }

    #[test]
    fn plans_jump_for_rip_relative_instruction_encoding() {
        let code = [0x48, 0x8D, 0x05, 0, 0, 0, 0, 0x90];
        let plan = plan_for(&code, 59, 0x2000).unwrap();

        assert_eq!(
            plan.strategy(),
            PatchStrategy::GuardedSplit {
                front_len: 5,
                back_len: 3,
            }
        );
        assert_eq!(plan.original_bytes(), code);
    }

    #[test]
    fn rejects_instruction_too_short_for_direct_jump() {
        let code = [0x48, 0x89, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90];
        let error = plan_for(&code, 60, 0x1000).unwrap_err();

        assert_eq!(
            error,
            PatchError::InstructionTooShort {
                address: 60,
                instruction_len: 3,
            }
        );
    }

    #[test]
    fn rejects_scan_from_different_code_bytes() {
        let scanner = InstructionScanner::default();
        let original = [0xB8, 1, 0, 0, 0, 0xC3, 0x90, 0x90];
        let stale_scan = scanner.scan(&original, 60).unwrap();
        let changed = [0x48, 0x89, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90];

        let error =
            JumpPatchPlan::from_scan(&scanner, &stale_scan, &changed, 60, 60, 0x1000).unwrap_err();

        assert_eq!(error, PatchError::RegionMismatch { address: 60 });
    }

    #[test]
    fn rejects_trampoline_outside_rel32_reach() {
        let code = [0xB8, 1, 0, 0, 0, 0xC3, 0x90, 0x90];
        let error = plan_for(&code, 0, u64::MAX).unwrap_err();

        assert_eq!(
            error,
            PatchError::TargetOutOfRange {
                address: 0,
                target: u64::MAX,
            }
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod live {
        use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        use std::thread;

        use super::JumpPatchPlan;
        use crate::patcher::{LiveJumpPatch, StalenessBudget};
        use crate::scanner::InstructionScanner;

        const PAGE_BYTES: usize = 4096;
        const FUNCTION_OFFSET: usize = 56;
        const SITE_OFFSET: usize = 60;
        const TARGET_OFFSET: usize = 128;

        struct DualMapping {
            writable: *mut u8,
            executable: *mut u8,
        }

        impl DualMapping {
            fn new() -> Self {
                let name = b"liteinst2-wordpatch-test\0";
                // SAFETY: valid NUL-terminated name and flags.
                let fd = unsafe {
                    libc::syscall(
                        libc::SYS_memfd_create,
                        name.as_ptr().cast::<libc::c_char>(),
                        libc::MFD_CLOEXEC,
                    ) as libc::c_int
                };
                assert!(fd >= 0, "memfd_create failed");

                // SAFETY: fd is valid and PAGE_BYTES is representable.
                assert_eq!(unsafe { libc::ftruncate(fd, PAGE_BYTES as libc::off_t) }, 0);

                // SAFETY: maps the complete memfd as a writable shared alias.
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

                // SAFETY: maps the same memfd as a W^X executable shared alias.
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

                // SAFETY: mappings retain references to the file description.
                assert_eq!(unsafe { libc::close(fd) }, 0);

                Self {
                    writable: writable.cast(),
                    executable: executable.cast(),
                }
            }

            fn install_fixture(&self) {
                let entry = [0xF3, 0x0F, 0x1E, 0xFA];
                let original = [0xB8, 1, 0, 0, 0, 0xC3, 0x90, 0x90];
                let target = [0xB8, 2, 0, 0, 0, 0xC3];

                // SAFETY: writable mapping covers all fixture offsets.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        entry.as_ptr(),
                        self.writable.add(FUNCTION_OFFSET),
                        entry.len(),
                    );
                    core::ptr::copy_nonoverlapping(
                        original.as_ptr(),
                        self.writable.add(SITE_OFFSET),
                        original.len(),
                    );
                    core::ptr::copy_nonoverlapping(
                        target.as_ptr(),
                        self.writable.add(TARGET_OFFSET),
                        target.len(),
                    );
                }
            }

            fn plan(&self) -> JumpPatchPlan {
                let scanner = InstructionScanner::default();
                // SAFETY: fixture contains eight initialized bytes at the site.
                let code =
                    unsafe { core::slice::from_raw_parts(self.writable.add(SITE_OFFSET), 8) };
                let site = self.executable as u64 + SITE_OFFSET as u64;
                let target = self.executable as u64 + TARGET_OFFSET as u64;
                let scan = scanner.scan(code, site).unwrap();
                JumpPatchPlan::from_scan(&scanner, &scan, code, site, site, target).unwrap()
            }

            fn function(&self) -> extern "C" fn() -> u32 {
                let address = self.executable as usize + FUNCTION_OFFSET;
                // SAFETY: fixture starts with a valid x86-64 function at address.
                unsafe { core::mem::transmute(address) }
            }

            fn writable_site(&self) -> *mut u8 {
                // SAFETY: SITE_OFFSET is within the writable mapping.
                unsafe { self.writable.add(SITE_OFFSET) }
            }
        }

        #[test]
        fn redirects_execution_and_restores_original_code() {
            let mapping = DualMapping::new();
            mapping.install_fixture();
            let function = mapping.function();
            assert_eq!(function(), 1);

            let plan = mapping.plan();
            let budget = StalenessBudget::new(10_000).unwrap();
            // SAFETY: dual mappings alias and intentionally remain mapped.
            let patch =
                unsafe { LiveJumpPatch::bind(plan, mapping.writable_site(), budget) }.unwrap();

            // SAFETY: fixture mappings satisfy the bind contract.
            unsafe { patch.apply() }.unwrap();
            assert_eq!(function(), 2);
            // SAFETY: fixture mappings satisfy the bind contract.
            assert_eq!(
                unsafe { patch.apply() },
                Err(super::PatchError::ExpectedBytesMismatch)
            );

            // SAFETY: fixture mappings satisfy the bind contract.
            unsafe { patch.revert() }.unwrap();
            assert_eq!(function(), 1);
            // SAFETY: fixture mappings satisfy the bind contract.
            assert_eq!(
                unsafe { patch.revert() },
                Err(super::PatchError::ExpectedBytesMismatch)
            );
        }

        #[test]
        fn redirects_execution_across_every_word_split() {
            let scanner = InstructionScanner::default();
            let entry = [0xF3, 0x0F, 0x1E, 0xFA];
            let original = [0xB8, 1, 0, 0, 0, 0xC3, 0x90, 0x90];
            let target_code = [0xB8, 2, 0, 0, 0, 0xC3];

            for site_offset in 57..64 {
                let mapping = DualMapping::new();
                let entry_offset = site_offset - entry.len();
                // SAFETY: all generated fixture offsets are within the mapping.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        entry.as_ptr(),
                        mapping.writable.add(entry_offset),
                        entry.len(),
                    );
                    core::ptr::copy_nonoverlapping(
                        original.as_ptr(),
                        mapping.writable.add(site_offset),
                        original.len(),
                    );
                    core::ptr::copy_nonoverlapping(
                        target_code.as_ptr(),
                        mapping.writable.add(TARGET_OFFSET),
                        target_code.len(),
                    );
                }

                let site = mapping.executable as u64 + site_offset as u64;
                let target = mapping.executable as u64 + TARGET_OFFSET as u64;
                let scan = scanner.scan(&original, site).unwrap();
                let plan = JumpPatchPlan::from_scan(&scanner, &scan, &original, site, site, target)
                    .unwrap();
                assert_eq!(
                    plan.strategy(),
                    super::PatchStrategy::GuardedSplit {
                        front_len: 64 - site_offset,
                        back_len: site_offset - 56,
                    }
                );

                let function_address = mapping.executable as usize + entry_offset;
                // SAFETY: fixture starts with a valid function at entry_offset.
                let function: extern "C" fn() -> u32 =
                    unsafe { core::mem::transmute(function_address) };
                assert_eq!(function(), 1);

                let budget = StalenessBudget::new(10_000).unwrap();
                // SAFETY: dual mappings alias and intentionally remain mapped.
                let patch =
                    unsafe { LiveJumpPatch::bind(plan, mapping.writable.add(site_offset), budget) }
                        .unwrap();
                // SAFETY: fixture mappings satisfy the bind contract.
                unsafe { patch.apply() }.unwrap();
                assert_eq!(function(), 2);
                // SAFETY: fixture mappings satisfy the bind contract.
                unsafe { patch.revert() }.unwrap();
                assert_eq!(function(), 1);
            }
        }

        #[test]
        fn concurrent_execution_observes_only_complete_versions() {
            let mapping = DualMapping::new();
            mapping.install_fixture();
            let function = mapping.function();
            let plan = mapping.plan();
            let budget = StalenessBudget::new(20_000).unwrap();
            // SAFETY: dual mappings alias and intentionally remain mapped.
            let patch =
                unsafe { LiveJumpPatch::bind(plan, mapping.writable_site(), budget) }.unwrap();

            let running = Arc::new(AtomicBool::new(true));
            let calls = Arc::new(AtomicU64::new(0));
            let invalid = Arc::new(AtomicBool::new(false));
            let mut workers = Vec::new();
            for _ in 0..4 {
                let running = Arc::clone(&running);
                let calls = Arc::clone(&calls);
                let invalid = Arc::clone(&invalid);
                workers.push(thread::spawn(move || {
                    while running.load(Ordering::Acquire) {
                        let value = function();
                        if value != 1 && value != 2 {
                            invalid.store(true, Ordering::Release);
                        }
                        calls.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }

            for _ in 0..5_000 {
                // SAFETY: fixture mappings satisfy the bind contract.
                unsafe { patch.apply() }.unwrap();
                // SAFETY: fixture mappings satisfy the bind contract.
                unsafe { patch.revert() }.unwrap();
            }

            running.store(false, Ordering::Release);
            for worker in workers {
                worker.join().unwrap();
            }

            assert!(!invalid.load(Ordering::Acquire));
            assert!(calls.load(Ordering::Relaxed) > 0);
            assert!(patch.handled_guard_traps() > 0);
            assert_eq!(function(), 1);
        }

        #[test]
        fn secondary_guarded_instruction_head_waits_and_retries() {
            const ENTRY: usize = 53;
            const SITE: usize = 57;
            const SECONDARY: usize = 62;
            const TARGET: usize = 128;

            let mapping = DualMapping::new();
            let endbr = [0xF3, 0x0F, 0x1E, 0xFA];
            let original = [0xB8, 1, 0, 0, 0];
            let ret = [0xC3];
            let target = [0xB8, 2, 0, 0, 0, 0xC3];
            // SAFETY: all fixture ranges are within the writable mapping.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    endbr.as_ptr(),
                    mapping.writable.add(ENTRY),
                    endbr.len(),
                );
                core::ptr::copy_nonoverlapping(
                    original.as_ptr(),
                    mapping.writable.add(SITE),
                    original.len(),
                );
                core::ptr::copy_nonoverlapping(
                    endbr.as_ptr(),
                    mapping.writable.add(SECONDARY),
                    endbr.len(),
                );
                core::ptr::copy_nonoverlapping(
                    ret.as_ptr(),
                    mapping.writable.add(SECONDARY + endbr.len()),
                    ret.len(),
                );
                core::ptr::copy_nonoverlapping(
                    target.as_ptr(),
                    mapping.writable.add(TARGET),
                    target.len(),
                );
            }

            let scanner = InstructionScanner::default();
            // SAFETY: fixture has ten initialized instruction bytes at SITE.
            let code = unsafe { core::slice::from_raw_parts(mapping.writable.add(SITE), 10) };
            let site = mapping.executable as u64 + SITE as u64;
            let target = mapping.executable as u64 + TARGET as u64;
            let scan = scanner.scan(code, site).unwrap();
            let plan = JumpPatchPlan::from_scan(&scanner, &scan, code, site, site, target).unwrap();
            assert_eq!(
                plan.guarded_instruction_offsets().collect::<Vec<_>>(),
                vec![0, 5]
            );

            let primary_address = mapping.executable as usize + ENTRY;
            let secondary_address = mapping.executable as usize + SECONDARY;
            // SAFETY: fixture contains valid functions at both addresses.
            let primary: extern "C" fn() -> u32 = unsafe { core::mem::transmute(primary_address) };
            // SAFETY: fixture contains a valid ENDBR64/RET function.
            let secondary: extern "C" fn() = unsafe { core::mem::transmute(secondary_address) };
            assert_eq!(primary(), 1);

            let budget = StalenessBudget::new(20_000).unwrap();
            // SAFETY: dual mappings alias and intentionally remain mapped.
            let patch =
                unsafe { LiveJumpPatch::bind(plan, mapping.writable.add(SITE), budget) }.unwrap();

            let running = Arc::new(AtomicBool::new(true));
            let calls = Arc::new(AtomicU64::new(0));
            let mut workers = Vec::new();
            for _ in 0..2 {
                let running = Arc::clone(&running);
                let calls = Arc::clone(&calls);
                workers.push(thread::spawn(move || {
                    while running.load(Ordering::Acquire) {
                        secondary();
                        calls.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }

            for _ in 0..5_000 {
                // SAFETY: fixture mappings satisfy the bind contract.
                unsafe { patch.apply() }.unwrap();
                // SAFETY: fixture mappings satisfy the bind contract.
                unsafe { patch.revert() }.unwrap();
            }

            running.store(false, Ordering::Release);
            for worker in workers {
                worker.join().unwrap();
            }

            assert!(calls.load(Ordering::Relaxed) > 0);
            assert!(patch.handled_guard_traps() > 0);
            assert_eq!(primary(), 1);
        }
    }
}
