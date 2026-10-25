//! Ordered, generation-bound transactions spanning several trusted core plans.
//!
//! Plans are composed against a virtual byte overlay. Every image and route is
//! staged before the first source store; a postwrite failure retains the whole
//! transaction behind the caller's poisoned lease. See `A2-COMPOSITION.md`.

use crate::composition::Composition;
use crate::contracts::*;
use crate::quiescent::{self, PlannedInstall};
use crate::trampoline::{ExecutableTrampoline, SavedExtendedStateLayout, TrampolineImage};

/// Aggregate transaction limits, independent of each member's search limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleBudget {
    /// Maximum number of constituent source rewrites.
    pub max_steps: usize,
    /// Maximum number of new executable virtual mappings.
    pub max_mappings: usize,
    /// Maximum sum of executable virtual mapping lengths.
    pub max_virtual_bytes: u64,
    /// Maximum newly allocated physical backing bytes.
    pub max_backing_bytes: u64,
    /// Maximum distance from the first to last generated mapping byte.
    pub max_virtual_span: u64,
}
impl Default for BundleBudget {
    fn default() -> Self {
        Self {
            max_steps: 64,
            max_mappings: 64,
            max_virtual_bytes: 512 * 1024,
            max_backing_bytes: 512 * 1024,
            max_virtual_span: 1 << 32,
        }
    }
}

/// Separate accounting for virtual placement and backing consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleMemory {
    /// Number of requested executable mappings, not measured kernel VMA merges.
    pub mappings: usize,
    /// Sum of all executable mapping lengths.
    pub virtual_bytes: u64,
    /// Physical allocation bytes; initially one private backing per mapping.
    pub backing_bytes: u64,
    /// Last mapping end minus first mapping start.
    pub virtual_span: u64,
}

/// Immutable original snapshots, ordered plans, final bytes and persistent locks.
#[derive(Clone, Debug)]
pub struct BundlePlan {
    identity: CodeIdentity,
    originals: Vec<ExpectedBytes>,
    final_bytes: Vec<ExpectedBytes>,
    steps: Vec<PatchPlan>,
    locks: Vec<AddressRange>,
    memory: BundleMemory,
}
impl BundlePlan {
    /// Common mapping incarnation and generation.
    pub const fn identity(&self) -> CodeIdentity {
        self.identity
    }
    /// Authoritative pre-transaction bytes. Member reads may instead see an overlay.
    pub fn originals(&self) -> &[ExpectedBytes] {
        &self.originals
    }
    /// Exact complete source snapshots after every member edit.
    pub fn final_bytes(&self) -> &[ExpectedBytes] {
        &self.final_bytes
    }
    /// Ordered steps; every member read authenticates the preceding overlay.
    pub fn steps(&self) -> &[PatchPlan] {
        &self.steps
    }
    /// Persistent ownership of writes, consumed pun bytes and store padding.
    pub fn locks(&self) -> &[AddressRange] {
        &self.locks
    }
    /// Aggregate mapping and physical memory accounting.
    pub const fn memory(&self) -> BundleMemory {
        self.memory
    }

    fn check(&self, lease: &QuiescenceLease<'_>, retiring: bool) -> Result<(), Refusal> {
        for step in &self.steps {
            lease.check(step)?;
        }
        for read in &self.originals {
            if !lease.covers(AddressRange::new(read.address, read.bytes.len())?) {
                return Err(Refusal::DependencyNotHeld);
            }
        }
        if retiring
            && self
                .steps
                .iter()
                .flat_map(|p| &p.parts().allocations)
                .any(|allocation| !lease.covers(allocation.range))
        {
            return Err(Refusal::DependencyNotHeld);
        }
        Ok(())
    }
}

/// Trusted emitted images and their checked composition. Construction is pure.
#[derive(Clone, Debug)]
pub struct PlannedBundle {
    plan: BundlePlan,
    images: Vec<TrampolineImage>,
}
impl PlannedBundle {
    /// Composes trusted plans against the supplied original snapshots.
    ///
    /// Caller order is explicit: a successor eviction can precede a pun which
    /// consumes its redirect. A member planned against stale original bytes is
    /// refused, even when that member's actual writes are disjoint. The planner
    /// must replan it against the preceding overlay. Arbitrary structural
    /// `PatchPlan`s cannot be injected through this constructor.
    pub fn compose(
        originals: Vec<ExpectedBytes>,
        members: Vec<PlannedInstall>,
        budget: BundleBudget,
    ) -> Result<Self, Refusal> {
        let identity = members
            .first()
            .ok_or(Refusal::InvalidPlan)?
            .plan()
            .parts()
            .identity;
        if members.len() > budget.max_steps {
            return Err(Refusal::AllocationUnavailable);
        }
        let mut composition = Composition::new(identity, originals)?;
        for member in &members {
            if member.plan().parts().profile != ApplicationProfile::InstallOnce {
                return Err(Refusal::InvalidPlan);
            }
            composition.append(member.plan())?;
        }
        let allocations: Vec<_> = members
            .iter()
            .flat_map(|m| &m.plan().parts().allocations)
            .collect();
        let virtual_bytes = allocations
            .iter()
            .try_fold(0_u64, |sum, a| sum.checked_add(a.range.len()))
            .ok_or(Refusal::InvalidRange)?;
        let low = allocations
            .iter()
            .map(|a| a.range.start())
            .min()
            .ok_or(Refusal::InvalidPlan)?;
        let high = allocations
            .iter()
            .map(|a| a.range.end())
            .max()
            .ok_or(Refusal::InvalidPlan)?;
        let memory = BundleMemory {
            mappings: allocations.len(),
            virtual_bytes,
            backing_bytes: virtual_bytes,
            virtual_span: high - low,
        };
        if memory.mappings > budget.max_mappings
            || memory.virtual_bytes > budget.max_virtual_bytes
            || memory.backing_bytes > budget.max_backing_bytes
            || memory.virtual_span > budget.max_virtual_span
        {
            return Err(Refusal::AllocationUnavailable);
        }
        Ok(Self {
            plan: BundlePlan {
                identity,
                originals: composition.originals().to_vec(),
                final_bytes: composition.final_bytes().to_vec(),
                locks: composition.locks().to_vec(),
                steps: members.iter().map(|member| member.plan().clone()).collect(),
                memory,
            },
            images: members
                .iter()
                .map(|member| member.image().clone())
                .collect(),
        })
    }
    /// Full inspectable transaction contract.
    pub const fn plan(&self) -> &BundlePlan {
        &self.plan
    }
    /// Every generated image and its explicit entry/state-comparison maps.
    pub fn images(&self) -> &[TrampolineImage] {
        &self.images
    }

    /// Installs every member with final source permissions already established.
    ///
    /// # Safety
    /// All aliases must satisfy [`WritableAlias::new`] through retirement. The
    /// lease excludes every source reader/executor/writer, alias, signal reentry
    /// and saved continuation. Every member's no-CET System V execution, stack,
    /// extended-state, callback and executable-fetch requirements must hold.
    /// Every single-plan publication obligation also applies, including the
    /// absence of application code-as-data accesses. When routes are present,
    /// SIGILL must remain unblocked on every executor and its disposition must
    /// remain owned by the router through retirement and execution drainage.
    pub unsafe fn publish(
        &self,
        aliases: &[WritableAlias],
        lease: &mut QuiescenceLease<'_>,
    ) -> Result<(InstalledBundle, BundleReceipt), PublicationFailure> {
        // SAFETY: forwards this method's caller contract.
        unsafe { self.publish_with(aliases, lease, || Ok(())) }
    }

    /// Installs all members, then finalizes source permissions before sync-core.
    ///
    /// # Safety
    /// Same requirements as [`Self::publish`]. `finalize` must establish final
    /// permissions without unwinding, changing bytes/identity or admitting any
    /// execution. On any postwrite error the entire bundle must remain gated.
    pub unsafe fn publish_with(
        &self,
        aliases: &[WritableAlias],
        lease: &mut QuiescenceLease<'_>,
        mut finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<(InstalledBundle, BundleReceipt), PublicationFailure> {
        self.plan.check(lease, false).map_err(before)?;
        quiescent::qualify_host().map_err(before)?;
        check_aliases(aliases).map_err(before)?;
        check_snapshots(aliases, &self.plan.originals).map_err(before)?;
        let stores = source_stores(&self.plan, aliases).map_err(before)?;
        let current = SavedExtendedStateLayout::detect()
            .map_err(|e| before(Refusal::Backend(e.to_string())))?;
        if self
            .images
            .iter()
            .any(|image| image.layout().saved_extended_state != current)
        {
            return Err(before(Refusal::UnsupportedSemantics(
                "extended-state layout changed since planning".into(),
            )));
        }
        quiescent::prepare_sync_core().map_err(before)?;
        let mut reservations = Vec::with_capacity(self.plan.locks.len());
        for range in &self.plan.locks {
            reservations.push(
                crate::trap::reserve(
                    range.start() as usize,
                    range.start() as usize,
                    range.end() as usize,
                    0,
                )
                .map_err(|_| before(Refusal::OwnershipConflict))?,
            );
        }
        let mut staged = Vec::with_capacity(self.images.len());
        for image in &self.images {
            staged.push(
                ExecutableTrampoline::allocate_image_at(image, image.address())
                    .map_err(|e| before(Refusal::Backend(e.to_string())))?,
            );
        }
        let routes: Vec<_> = self
            .plan
            .steps
            .iter()
            .flat_map(|p| &p.parts().obligations)
            .filter_map(|obligation| match obligation {
                EntryObligation::Routed(route) => Some(*route),
                _ => None,
            })
            .collect();
        let mut routing = if routes.is_empty() {
            None
        } else {
            crate::entry_router::prepare().map_err(before)?;
            // SAFETY: all emitted images are initialized and the complete lease is held.
            Some(unsafe { crate::entry_router::stage(&routes) }.map_err(before)?)
        };
        self.plan.check(lease, false).map_err(before)?;
        check_snapshots(aliases, &self.plan.originals).map_err(before)?;
        if routing.is_some() {
            crate::entry_router::verify().map_err(before)?;
        }
        let trampolines: Vec<_> = staged.into_iter().map(|image| image.commit()).collect();
        for trampoline in &trampolines {
            trampoline.publish_program_counter_mappings();
        }
        if let Some(registration) = routing.as_mut() {
            registration.commit();
        }
        let installed = InstalledBundle {
            plan: self.plan.clone(),
            aliases: aliases.to_vec(),
            stores,
            reservations,
            routing,
            trampolines,
            retired: false,
        };
        lease.poison();
        for store in &installed.stores {
            // SAFETY: every span was authenticated and resolved under the held lease.
            unsafe { store.write(false) };
        }
        if let Err(reason) = finalize().and_then(|()| quiescent::sync_core()) {
            return Err(PublicationFailure {
                reason,
                stage: FailureStage::KeepGated,
            });
        }
        lease.publication_completed();
        let receipt = BundleReceipt {
            plan: self.plan.clone(),
        };
        Ok((installed, receipt))
    }
}

/// Caller-certified writable alias of a source extent.
#[derive(Clone, Copy, Debug)]
pub struct WritableAlias {
    range: AddressRange,
    pointer: *mut u8,
}
impl WritableAlias {
    /// Binds an executable extent to its writable bytes without accessing them.
    ///
    /// # Safety
    /// `pointer` aliases every byte in `range`, at the same byte offset, and
    /// stays readable/writable whenever publication or retirement accesses it.
    /// The mapping identity and backing cannot change while a bundle uses it.
    /// Different source ranges may not secretly alias the same physical bytes.
    /// All accesses are excluded by the caller's leases. Pun stores additionally
    /// require matching virtual/writable cache-line offsets (checked at publish).
    pub unsafe fn new(range: AddressRange, pointer: *mut u8) -> Result<Self, Refusal> {
        if pointer.is_null()
            || (pointer as usize)
                .checked_add(range.len() as usize)
                .is_none()
        {
            return Err(Refusal::InvalidRange);
        }
        Ok(Self { range, pointer })
    }
    /// Executable extent represented by this alias.
    pub const fn range(self) -> AddressRange {
        self.range
    }
}

/// Evidence issued only after every bundle store, permission operation and sync.
#[derive(Clone, Debug)]
pub struct BundleReceipt {
    plan: BundlePlan,
}
impl BundleReceipt {
    /// Exact completed transaction, including the original and final images.
    pub const fn plan(&self) -> &BundlePlan {
        &self.plan
    }
}

/// Permanently active transaction; there is no sampling arm/disarm operation.
///
/// Drop retains all reachable code, routes and byte ownership. Explicit gated
/// retirement releases source ownership; code/metadata remain process-lifetime.
pub struct InstalledBundle {
    plan: BundlePlan,
    aliases: Vec<WritableAlias>,
    stores: Vec<SourceStore>,
    reservations: Vec<crate::trap::PendingTrapSite>,
    routing: Option<crate::entry_router::RouteRegistration>,
    trampolines: Vec<ExecutableTrampoline>,
    retired: bool,
}
impl InstalledBundle {
    /// Installed transaction contract.
    pub const fn plan(&self) -> &BundlePlan {
        &self.plan
    }
    /// All retained executable images.
    pub fn trampolines(&self) -> &[ExecutableTrampoline] {
        &self.trampolines
    }
    /// Whether original bytes and source ownership have been restored.
    pub const fn is_retired(&self) -> bool {
        self.retired
    }
    /// Number of owned illegal-entry transfers across the whole transaction.
    pub fn routed_entries(&self) -> u64 {
        self.routing.as_ref().map_or(0, |r| r.handled())
    }
    /// Restores every member in reverse order with permissions already suitable.
    ///
    /// # Safety
    /// The original aliases must be writable and the lease must drain all source
    /// and generated execution, saved continuations, signal references and readers.
    pub unsafe fn retire(
        &mut self,
        lease: &mut QuiescenceLease<'_>,
    ) -> Result<(), PublicationFailure> {
        // SAFETY: forwards the original/generation execution-drain contract.
        unsafe { self.retire_with(lease, || Ok(())) }
    }
    /// Restores every member, finalizes permissions and synchronizes as one unit.
    ///
    /// # Safety
    /// Same contract as [`Self::retire`]. The finalizer must not unwind, admit
    /// execution or change source bytes/identity; it must establish final permissions.
    pub unsafe fn retire_with(
        &mut self,
        lease: &mut QuiescenceLease<'_>,
        mut finalize: impl FnMut() -> Result<(), Refusal>,
    ) -> Result<(), PublicationFailure> {
        self.plan.check(lease, !self.retired).map_err(before)?;
        if self.retired {
            return Ok(());
        }
        if self.routing.is_some() {
            crate::entry_router::verify().map_err(before)?;
        }
        check_snapshots(&self.aliases, &self.plan.final_bytes).map_err(before)?;
        quiescent::prepare_sync_core().map_err(before)?;
        lease.poison();
        for store in self.stores.iter().rev() {
            // SAFETY: every source/generated reference is drained and aliases writable.
            unsafe { store.write(true) };
        }
        if let Err(reason) = finalize().and_then(|()| quiescent::sync_core()) {
            return Err(PublicationFailure {
                reason,
                stage: FailureStage::KeepGated,
            });
        }
        if let Some(routing) = &self.routing {
            routing.deactivate();
        }
        self.reservations.clear();
        self.retired = true;
        lease.publication_completed();
        Ok(())
    }
}
impl Drop for InstalledBundle {
    fn drop(&mut self) {
        for reservation in self.reservations.drain(..) {
            std::mem::forget(reservation);
        }
    }
}

struct SourceStore {
    pointer: *mut u8,
    before: Vec<u8>,
    after: Vec<u8>,
    single: bool,
}
impl SourceStore {
    unsafe fn write(&self, restore: bool) {
        let bytes = if restore { &self.before } else { &self.after };
        if self.single {
            // SAFETY: preflight checked exact byte/word/dword span and line alignment.
            unsafe { quiescent::single_store(self.pointer, bytes) };
        } else {
            // SAFETY: preflight resolved the entire source edit under the held lease.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.pointer, bytes.len()) };
        }
    }
}
fn before(reason: Refusal) -> PublicationFailure {
    PublicationFailure {
        reason,
        stage: FailureStage::BeforeWrite,
    }
}
fn check_aliases(aliases: &[WritableAlias]) -> Result<(), Refusal> {
    for (i, alias) in aliases.iter().enumerate() {
        if aliases[..i]
            .iter()
            .any(|other| other.range.overlaps(alias.range))
        {
            return Err(Refusal::InvalidRange);
        }
    }
    Ok(())
}
fn pointer(aliases: &[WritableAlias], range: AddressRange) -> Result<*mut u8, Refusal> {
    let alias = aliases
        .iter()
        .find(|alias| alias.range.covers(range))
        .ok_or(Refusal::InvalidRange)?;
    // SAFETY: alias construction certifies all offsets within this extent.
    Ok(unsafe {
        alias
            .pointer
            .add((range.start() - alias.range.start()) as usize)
    })
}
fn check_snapshots(aliases: &[WritableAlias], snapshots: &[ExpectedBytes]) -> Result<(), Refusal> {
    for read in snapshots {
        let pointer = pointer(aliases, AddressRange::new(read.address, read.bytes.len())?)?;
        // SAFETY: caller's alias lifetime and lease exclude concurrent byte accesses.
        if unsafe { std::slice::from_raw_parts(pointer, read.bytes.len()) } != read.bytes {
            return Err(Refusal::ExpectedBytesChanged);
        }
    }
    Ok(())
}
fn source_stores(
    plan: &BundlePlan,
    aliases: &[WritableAlias],
) -> Result<Vec<SourceStore>, Refusal> {
    let mut stores = Vec::new();
    for step in &plan.steps {
        let (edits, single) = match &step.parts().kind {
            PlanKind::GeneralizedPun(pun) => (std::slice::from_ref(&pun.store), true),
            PlanKind::Relocation => (step.parts().writes.as_slice(), false),
        };
        for edit in edits {
            let range = AddressRange::new(edit.address, edit.bytes.len())?;
            let pointer = pointer(aliases, range)?;
            if single && pointer as usize % 64 != edit.address as usize % 64 {
                return Err(Refusal::InvalidRange);
            }
            let read = step
                .parts()
                .reads
                .iter()
                .find(|read| {
                    AddressRange::new(read.address, read.bytes.len())
                        .is_ok_and(|read_range| read_range.covers(range))
                })
                .ok_or(Refusal::InvalidPlan)?;
            let offset = (edit.address - read.address) as usize;
            stores.push(SourceStore {
                pointer,
                before: read.bytes[offset..offset + edit.bytes.len()].to_vec(),
                after: edit.bytes.clone(),
                single,
            });
        }
    }
    Ok(stores)
}
