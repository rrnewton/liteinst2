//! Experimental instruction-stream-synchronized WordPatch publication.
//!
//! This separate protocol has no staleness-delay fallback. It is not a claim
//! that arbitrary live entries, signal masks, saved PCs or callbacks are safe.
//! A first instruction of 5..=8 bytes is the initial admitted geometry; all
//! additional entry, alias and signal obligations below remain mandatory.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::PatchStrategy;
use super::{JumpPatchPlan, PatchError};
use crate::sync_core::{SyncCore, SyncCoreError};
use core::fmt;

/// Direction of a synchronized transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Replace the original instruction with its planned redirect.
    Apply,
    /// Restore the planned original instruction.
    Revert,
}

/// Last completed publication action; a failed barrier leaves this unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Every member is exclusively held and all expected bytes are checked.
    Prepared,
    /// All split members have their front fragments guarded.
    GuardsPublished,
    /// First process-wide instruction-stream synchronization completed.
    GuardsSynchronized,
    /// All split members have their new back words.
    BacksPublished,
    /// Second process-wide instruction-stream synchronization completed.
    BacksSynchronized,
    /// All final front words, including single-line members, are published.
    FrontsPublished,
    /// Final synchronization completed and writer leases were released.
    Complete,
    /// A failure before any store released every acquired writer lease.
    Aborted,
}

/// Why a transition could not be prepared or advanced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPatchError {
    /// Existing scan, geometry, signal-route or ownership refusal.
    Patch(PatchError),
    /// The prepared synchronization capability failed; no delay substitutes.
    Synchronize(SyncCoreError),
    /// The first original instruction is not the entire 5..=8-byte displacement.
    UnsupportedInstruction,
    /// The batch has no members.
    EmptyBatch,
    /// Two members duplicate or overlap their actual write envelopes.
    OverlappingMembers,
    /// A binding was inherited from a different process.
    DifferentProcess,
    /// The transition was already aborted and cannot be resumed.
    Aborted,
    /// An advance unwound before recording its complete result.
    IncompleteOperation,
}

impl fmt::Display for SyncPatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "synchronized patch failed: {self:?}")
    }
}
impl std::error::Error for SyncPatchError {}
impl From<PatchError> for SyncPatchError {
    fn from(value: PatchError) -> Self {
        Self::Patch(value)
    }
}
impl From<SyncCoreError> for SyncPatchError {
    fn from(value: SyncCoreError) -> Self {
        Self::Synchronize(value)
    }
}

/// Observable progress, with no implied callback drain or batch atomicity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Last completed phase.
    pub phase: Phase,
    /// Number of members in this transition.
    pub members: usize,
    /// Successful publication barriers (exactly three on completion).
    pub synchronizations: usize,
    /// True once at least one executable-alias store occurred.
    pub mutated: bool,
    /// True while every member's writer lease remains held.
    pub writer_ownership_retained: bool,
    /// First terminal failure, retained without implicit retries or rollback.
    pub failure: Option<SyncPatchError>,
}

/// An advance refusal together with the exact retained transition state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Refusal or failed operating-system operation.
    pub error: SyncPatchError,
    /// Progress at failure; a mutated failure retains all writer ownership.
    pub receipt: Receipt,
}

/// Process-lifetime mapping binding for the separate synchronized protocol.
pub struct SyncJumpPatch {
    plan: JumpPatchPlan,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    native: NativePatch,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct NativePatch {
    writable: *mut u8,
    site: &'static crate::trap::TrapSite,
    capability: SyncCore,
    process: libc::pid_t,
    canonical_tail: [u8; 3],
    envelope: (usize, usize),
    writable_envelope: (usize, usize),
    // Split-word padding is authenticated at bind and on every transition.
    padding: Option<([u8; 8], [u8; 8])>,
}

// SAFETY: construction requires permanent aliases and exclusive registration;
// begin_jump serializes every overlapping writer before any load/store.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe impl Send for SyncJumpPatch {}
// SAFETY: native mutable access is protected by process-lifetime writer leases.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe impl Sync for SyncJumpPatch {}

impl SyncJumpPatch {
    /// Binds an existing plan without using or changing its legacy publisher.
    ///
    /// The capability is checked before registration or memory mutation. A
    /// successful bind retains the usual process-lifetime trap reservation.
    ///
    /// # Safety
    ///
    /// The writable pointer aliases the executable plan exactly, with identical
    /// cache-line offsets. The planned cache-line geometry must match every
    /// processor that may execute this code. Both aliases, their complete aligned write envelope,
    /// and every old/new jump target must remain mapped for process lifetime.
    /// Both aliases use normal cacheable write-back memory (not device memory).
    /// The source and padding are readable; the writable alias permits all
    /// actual stores. No other alias, process or unregistered writer may modify
    /// them. Binding itself excludes concurrent writes while padding is read.
    ///
    /// Every possible entry and saved resume PC is an original instruction head;
    /// none enters the interior of the displaced first instruction. The target
    /// implements the complete intended replacement semantics, including any
    /// required original effects and continuations.
    /// All execution threads keep SIGTRAP unblocked with this router installed,
    /// including through signal return and late guard delivery. The writer must
    /// not execute guarded code or be interrupted by a handler that does so.
    /// These are proof obligations, not runtime qualification supplied by this
    /// constructor. Shared cross-process aliases and runtime fork during a live
    /// transition are excluded. No code-as-data observer may rely on atomic
    /// visibility of the multiword or multimember transition.
    pub unsafe fn bind(
        plan: JumpPatchPlan,
        writable: *mut u8,
        capability: SyncCore,
    ) -> Result<Self, SyncPatchError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (plan, writable, capability);
            Err(PatchError::UnsupportedPlatform.into())
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            use iced_x86::{Decoder, DecoderOptions};
            let original = plan.original_bytes();
            let instruction =
                Decoder::with_ip(64, &original, plan.execute_address(), DecoderOptions::NONE)
                    .decode();
            if instruction.is_invalid()
                || !(5..=8).contains(&instruction.len())
                || instruction.len() != plan.displaced_len()
            {
                return Err(SyncPatchError::UnsupportedInstruction);
            }
            if writable.is_null() {
                return Err(PatchError::NullWritableAddress.into());
            }
            let address = usize::try_from(plan.execute_address()).map_err(|_| {
                PatchError::AddressNotRepresentable {
                    address: plan.execute_address(),
                }
            })?;
            let line = plan.cache_line.get();
            if line < 8 || !line.is_power_of_two() || line > 4096 {
                return Err(PatchError::UnsupportedCacheLineSize { bytes: line }.into());
            }
            (writable as usize)
                .checked_add(8)
                .ok_or(PatchError::AddressRangeOverflow)?;
            if address % line != writable as usize % line {
                return Err(PatchError::AliasAlignmentMismatch.into());
            }
            let (start, end, padding) = match plan.strategy() {
                PatchStrategy::AtomicWord => (
                    address,
                    address
                        .checked_add(8)
                        .ok_or(PatchError::AddressRangeOverflow)?,
                    None,
                ),
                PatchStrategy::GuardedSplit { front_len, .. } => {
                    let boundary = address
                        .checked_add(front_len)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    let start = boundary
                        .checked_sub(8)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    let end = boundary
                        .checked_add(8)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    let alias_boundary = (writable as usize)
                        .checked_add(front_len)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    if alias_boundary % 8 != 0 {
                        return Err(PatchError::AliasAlignmentMismatch.into());
                    }
                    let alias_front = alias_boundary
                        .checked_sub(8)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    alias_boundary
                        .checked_add(8)
                        .ok_or(PatchError::AddressRangeOverflow)?;
                    // SAFETY: caller certifies the complete readable envelope.
                    let front = unsafe { super::load_unaligned_word(alias_front as *const u8) }
                        .to_le_bytes();
                    // SAFETY: same complete-envelope contract.
                    let back = unsafe { super::load_unaligned_word(alias_boundary as *const u8) }
                        .to_le_bytes();
                    (start, end, Some((front, back)))
                }
            };
            let alias_start = (writable as usize)
                .checked_sub(address - start)
                .ok_or(PatchError::AddressRangeOverflow)?;
            let alias_end = alias_start
                .checked_add(end - start)
                .ok_or(PatchError::AddressRangeOverflow)?;
            capability.synchronize()?;
            crate::trap::prepare().map_err(super::map_trap_error)?;
            crate::trap::verify_synchronized_router().map_err(super::map_trap_error)?;
            let displaced_end = address
                .checked_add(plan.displaced_len())
                .ok_or(PatchError::AddressRangeOverflow)?;
            let (site, canonical) = crate::trap::register_jump(
                address,
                start,
                end,
                plan.guard_mask,
                displaced_end,
                matches!(plan.strategy(), PatchStrategy::AtomicWord).then_some(original),
            )
            .map_err(super::map_trap_error)?;
            let canonical_tail = canonical.unwrap_or(original)[5..]
                .try_into()
                .expect("three-byte tail");
            // SAFETY: getpid has no preconditions.
            let process = unsafe { libc::getpid() };
            Ok(Self {
                plan,
                native: NativePatch {
                    writable,
                    site,
                    capability,
                    process,
                    canonical_tail,
                    envelope: (start, end),
                    writable_envelope: (alias_start, alias_end),
                    padding,
                },
            })
        }
    }

    /// Immutable plan whose semantics remain caller-certified.
    pub fn plan(&self) -> &JumpPatchPlan {
        &self.plan
    }

    /// Genuine owned guard deliveries observed by the process-lifetime router.
    pub fn handled_guard_traps(&self) -> u64 {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            self.native.site.handled_traps()
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            0
        }
    }
}

/// An explicitly advanced batch holding every member until final completion.
///
/// The phases are ordered, but the batch is not an atomic switch: application
/// threads can observe individual final redirects as they are published. Drop
/// releases a prepared, untouched batch. Drop after any mutation deliberately
/// keeps all process-lifetime WRITING leases held; it neither restores code nor
/// frees routes. Losing such a handle leaves an unrecoverable poisoned batch.
/// Every failure is terminal for this handle. There is no retry, recovery or
/// rollback API. A final-barrier failure may already expose final redirects;
/// retained writer ownership does not claim that all execution is still trapped.
pub struct SynchronizedBatch<'a> {
    state: State,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    members: Vec<Member<'a>>,
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    marker: core::marker::PhantomData<&'a SyncJumpPatch>,
}

#[derive(Clone, Copy)]
struct State {
    phase: Phase,
    mutated: bool,
    synchronizations: usize,
    held: bool,
    members: usize,
    failure: Option<SyncPatchError>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct Member<'a> {
    patch: &'a SyncJumpPatch,
    expected: [u8; 8],
    replacement: [u8; 8],
    front_address: *mut u8,
    front_original: u64,
    front_guard: u64,
    front_final: u64,
    back: Option<(*mut u8, u64, u64)>,
}

impl<'a> SynchronizedBatch<'a> {
    /// Acquires all writer leases and authenticates every member before stores.
    ///
    /// # Safety
    /// Every bind contract remains true for the entire transition and any
    /// late guard delivery. No signal handler on the writer thread may execute
    /// these envelopes. On a retained failure, keep mappings/routes alive and
    /// do not admit a competing writer, even if final bytes already appear.
    pub unsafe fn prepare(
        patches: &[&'a SyncJumpPatch],
        direction: Direction,
    ) -> Result<Self, SyncPatchError> {
        if patches.is_empty() {
            return Err(SyncPatchError::EmptyBatch);
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = direction;
            Err(PatchError::UnsupportedPlatform.into())
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let mut ordered = patches.to_vec();
            ordered.sort_by_key(|p| p.native.envelope.0);
            disjoint(
                &ordered
                    .iter()
                    .map(|p| p.native.envelope)
                    .collect::<Vec<_>>(),
            )?;
            let mut aliases: Vec<_> = ordered.iter().map(|p| p.native.writable_envelope).collect();
            aliases.sort_unstable();
            disjoint(&aliases)?;
            crate::trap::verify_synchronized_router().map_err(super::map_trap_error)?;
            // SAFETY: getpid has no preconditions.
            let process = unsafe { libc::getpid() };
            if ordered.iter().any(|p| p.native.process != process) {
                return Err(SyncPatchError::DifferentProcess);
            }
            let mut batch = Self {
                state: State {
                    phase: Phase::Prepared,
                    mutated: false,
                    synchronizations: 0,
                    held: true,
                    members: ordered.len(),
                    failure: None,
                },
                members: Vec::with_capacity(ordered.len()),
            };
            for patch in ordered {
                let (mut expected, mut replacement) = match direction {
                    Direction::Apply => {
                        (patch.plan.original_bytes(), patch.plan.replacement_bytes())
                    }
                    Direction::Revert => {
                        (patch.plan.replacement_bytes(), patch.plan.original_bytes())
                    }
                };
                expected[5..].copy_from_slice(&patch.native.canonical_tail);
                replacement[5..].copy_from_slice(&patch.native.canonical_tail);
                patch
                    .native
                    .site
                    .begin_jump(&mut expected, &mut replacement)
                    .map_err(|e| match e {
                        crate::trap::JumpError::Registry(e) => {
                            SyncPatchError::Patch(super::map_trap_error(e))
                        }
                        crate::trap::JumpError::ExpectedBytesMismatch => {
                            SyncPatchError::Patch(PatchError::ExpectedBytesMismatch)
                        }
                    })?;
                // Record the acquired lease before any fallible byte check.
                batch.members.push(Member {
                    patch,
                    expected,
                    replacement,
                    front_address: patch.native.writable,
                    front_original: 0,
                    front_guard: 0,
                    front_final: 0,
                    back: None,
                });
            }
            for member in &mut batch.members {
                // SAFETY: every writer lease is acquired, aliases satisfy bind.
                unsafe {
                    member.preflight()?;
                }
            }
            Ok(batch)
        }
    }

    /// Returns progress without changing executable bytes or synchronization.
    pub fn receipt(&self) -> Receipt {
        self.state.receipt()
    }

    /// Performs exactly the next store phase or one process-wide barrier.
    ///
    /// A failed transition is terminal: later calls return the same retained
    /// failure without invoking a barrier or writing bytes.
    /// A failure before any store releases leases and marks Aborted; a failure
    /// after any store leaves the phase and all leases intact. Complete is
    /// idempotent. This method does not wait for callbacks or reclaim code.
    ///
    /// # Safety
    /// The contracts of bind and prepare still hold, including lifetime and
    /// all-thread signal/entry proofs. Do not call from a guarded instruction.
    pub unsafe fn advance(&mut self) -> Result<Receipt, Failure> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            Err(Failure {
                error: PatchError::UnsupportedPlatform.into(),
                receipt: self.receipt(),
            })
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let mut work = NativeWork {
                members: &mut self.members,
            };
            self.state.advance(&mut work)
        }
    }
}

impl Drop for SynchronizedBatch<'_> {
    fn drop(&mut self) {
        if self.state.held && !self.state.mutated {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            self.state.abandon(&mut NativeWork {
                members: &mut self.members,
            });
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            {
                self.state.held = false;
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
trait Work {
    fn verify(&mut self) -> Result<(), SyncPatchError>;
    fn has_split(&self) -> bool;
    fn guards(&mut self);
    fn backs(&mut self);
    fn fronts(&mut self);
    fn synchronize(&mut self) -> Result<(), SyncPatchError>;
    fn release(&mut self, committed: bool);
}

impl State {
    fn receipt(self) -> Receipt {
        Receipt {
            phase: self.phase,
            members: self.members,
            synchronizations: self.synchronizations,
            mutated: self.mutated,
            writer_ownership_retained: self.held,
            failure: self.failure,
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn abandon(&mut self, work: &mut impl Work) {
        if self.held && !self.mutated {
            work.release(false);
            self.held = false;
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn advance(&mut self, work: &mut impl Work) -> Result<Receipt, Failure> {
        if let Some(error) = self.failure {
            return Err(Failure {
                error,
                receipt: self.receipt(),
            });
        }
        if self.phase == Phase::Complete {
            return Ok(self.receipt());
        }
        if self.phase == Phase::Aborted {
            return Err(Failure {
                error: SyncPatchError::Aborted,
                receipt: self.receipt(),
            });
        }
        // An unwind must not turn an uncertain partial phase into a retry.
        self.failure = Some(SyncPatchError::IncompleteOperation);
        let operation = (|| {
            work.verify()?;
            self.phase = match self.phase {
                Phase::Prepared => {
                    self.mutated |= work.has_split();
                    work.guards();
                    Phase::GuardsPublished
                }
                Phase::GuardsPublished => {
                    work.synchronize()?;
                    self.synchronizations += 1;
                    Phase::GuardsSynchronized
                }
                Phase::GuardsSynchronized => {
                    self.mutated |= work.has_split();
                    work.backs();
                    Phase::BacksPublished
                }
                Phase::BacksPublished => {
                    work.synchronize()?;
                    self.synchronizations += 1;
                    Phase::BacksSynchronized
                }
                Phase::BacksSynchronized => {
                    self.mutated = true;
                    work.fronts();
                    Phase::FrontsPublished
                }
                Phase::FrontsPublished => {
                    work.synchronize()?;
                    self.synchronizations += 1;
                    work.release(true);
                    self.held = false;
                    Phase::Complete
                }
                Phase::Complete | Phase::Aborted => unreachable!("terminal checked above"),
            };
            Ok(())
        })();
        match operation {
            Ok(()) => {
                self.failure = None;
                Ok(self.receipt())
            }
            Err(error) => {
                self.failure = Some(error);
                if !self.mutated {
                    work.release(false);
                    self.held = false;
                    self.phase = Phase::Aborted;
                }
                Err(Failure {
                    error,
                    receipt: self.receipt(),
                })
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Member<'_> {
    unsafe fn preflight(&mut self) -> Result<(), SyncPatchError> {
        match self.patch.plan.strategy() {
            PatchStrategy::AtomicWord => {
                // SAFETY: exclusive complete eight-byte alias from bind.
                self.front_original = unsafe { super::load_unaligned_word(self.front_address) };
                if self.front_original.to_le_bytes() != self.expected {
                    return Err(PatchError::ExpectedBytesMismatch.into());
                }
                self.front_guard = self.front_original;
                self.front_final = u64::from_le_bytes(self.replacement);
            }
            PatchStrategy::GuardedSplit { front_len, .. } => {
                // SAFETY: bind checked both aligned envelope words.
                let boundary = unsafe { self.patch.native.writable.add(front_len) };
                // SAFETY: the complete preceding word belongs to the envelope.
                self.front_address = unsafe { boundary.sub(8) };
                let (pad_front, pad_back) = self.patch.native.padding.expect("split padding");
                // SAFETY: both readable words are exclusively held.
                let actual_front = unsafe { super::load_unaligned_word(self.front_address) };
                // SAFETY: same bound for the second complete word.
                let actual_back = unsafe { super::load_unaligned_word(boundary) };
                let layout = split_words(
                    front_len,
                    self.expected,
                    self.replacement,
                    [pad_front, pad_back],
                    [actual_front.to_le_bytes(), actual_back.to_le_bytes()],
                )?;
                self.front_original = actual_front;
                self.front_guard = u64::from_le_bytes(layout.guard);
                self.front_final = u64::from_le_bytes(layout.front);
                self.back = Some((boundary, actual_back, u64::from_le_bytes(layout.back)));
            }
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct NativeWork<'a, 'b> {
    members: &'a mut [Member<'b>],
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Work for NativeWork<'_, '_> {
    fn verify(&mut self) -> Result<(), SyncPatchError> {
        // SAFETY: getpid has no preconditions.
        let process = unsafe { libc::getpid() };
        if self
            .members
            .iter()
            .any(|m| m.patch.native.process != process)
        {
            return Err(SyncPatchError::DifferentProcess);
        }
        crate::trap::verify_synchronized_router().map_err(super::map_trap_error)?;
        Ok(())
    }
    fn has_split(&self) -> bool {
        self.members.iter().any(|m| m.back.is_some())
    }
    fn guards(&mut self) {
        for m in self.members.iter() {
            if m.back.is_some() {
                // SAFETY: preflight holds and authenticates the whole envelope;
                // a single aligned MOV guards every front-fragment byte.
                unsafe {
                    super::store_unaligned_word(m.front_address, m.front_guard);
                }
            }
        }
    }
    fn backs(&mut self) {
        for m in self.members.iter() {
            if let Some((address, _, value)) = m.back {
                // SAFETY: the first barrier completed; all fronts stay guarded.
                unsafe {
                    super::store_unaligned_word(address, value);
                }
            }
        }
    }
    fn fronts(&mut self) {
        for m in self.members.iter() {
            // SAFETY: the second barrier completed. A single MOV publishes the
            // aligned split front or the complete single-line atomic word.
            unsafe {
                super::store_unaligned_word(m.front_address, m.front_final);
            }
        }
    }
    fn synchronize(&mut self) -> Result<(), SyncPatchError> {
        self.members[0]
            .patch
            .native
            .capability
            .synchronize()
            .map_err(Into::into)
    }
    fn release(&mut self, committed: bool) {
        for m in self.members.iter() {
            m.patch
                .native
                .site
                .finish_jump(committed.then_some(m.replacement));
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn disjoint(sorted: &[(usize, usize)]) -> Result<(), SyncPatchError> {
    if sorted.iter().any(|&(start, end)| start >= end)
        || sorted.windows(2).any(|pair| pair[0].1 > pair[1].0)
    {
        return Err(SyncPatchError::OverlappingMembers);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct SplitWords {
    guard: [u8; 8],
    front: [u8; 8],
    back: [u8; 8],
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn split_words(
    front_len: usize,
    expected: [u8; 8],
    replacement: [u8; 8],
    padding: [[u8; 8]; 2],
    actual: [[u8; 8]; 2],
) -> Result<SplitWords, SyncPatchError> {
    assert!((1..8).contains(&front_len));
    let offset = 8 - front_len;
    let mut old_front = padding[0];
    let mut old_back = padding[1];
    old_front[offset..].copy_from_slice(&expected[..front_len]);
    old_back[..offset].copy_from_slice(&expected[front_len..]);
    if actual != [old_front, old_back] {
        return Err(PatchError::ExpectedBytesMismatch.into());
    }
    let mut front = old_front;
    let mut back = old_back;
    front[offset..].copy_from_slice(&replacement[..front_len]);
    back[..offset].copy_from_slice(&replacement[front_len..]);
    let mut guard = old_front;
    guard[offset..].fill(super::BREAKPOINT_OPCODE);
    Ok(SplitWords { guard, front, back })
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
