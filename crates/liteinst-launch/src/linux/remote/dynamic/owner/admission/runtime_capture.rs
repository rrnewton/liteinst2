//! Initial runtime byte custody. Complete VMA identities and bounded dependency
//! windows remain different objects. No scan, plan, guard or release is created.
use super::super::Owner;
use super::super::bootstrap::BootstrapMm;
use super::super::lifecycle::NativeLifecycle;
use super::super::trusted::AdmissionStop;
use super::census::BudgetCharge;
use super::source_identity::{
    ExecutableIdentity, HeldSourceRead, InitialReadScratch, OriginalSourceRead, SourceInventory,
    SourceReadProgress, SourceVma,
};
use crate::gate::GateError;
use crate::linux::remote::MAX_XSTATE;
use crate::{DynamicEventKind, DynamicStop, EntryEvidence, LaunchError, RegisterSnapshot};
use iced_x86::{Decoder, DecoderOptions};
use liteinst_admission::entries::{Completeness, EntryProvenance};
use liteinst_admission::scan::{Boundary, Snapshot, WriteControl};
use liteinst_admission::{AddressRange, Generation, MappingId};
use liteinst2::contracts::CodeIdentity;
use std::io::ErrorKind;
use std::mem::size_of;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::time::Instant;

mod current;
pub(super) use current::{CapturedRuntimeRead, RuntimeCatalogCheckpoint, RuntimeWindowProof};
mod geometry;
use geometry::{VmaGeometry, WindowGeometry};
#[cfg(test)]
mod tests;

const MAP_BYTES: usize = 64 * 1024;
const MAX_WINDOW_BYTES: usize = 64 * 1024;
const MAX_VMAS: usize = 64;
const MAX_WINDOWS: usize = 64;
const ENTRY_PATH_BYTES: usize = 4096;

/// Private resource profile; root's public runtime options validate/adapt it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InitialCaptureProfile {
    pub(super) max_vmas: usize,
    pub(super) max_windows: usize,
    pub(super) max_window_bytes: usize,
    /// Includes every overlapping dependency byte, not only target-page bytes.
    pub(super) max_total_capture_bytes: usize,
}

impl InitialCaptureProfile {
    pub(super) fn validate(self) -> Result<Self, GateError> {
        if !(1..=MAX_VMAS).contains(&self.max_vmas)
            || !(1..=MAX_WINDOWS).contains(&self.max_windows)
            || self.max_window_bytes > MAX_WINDOW_BYTES
            || self.max_window_bytes % geometry::PAGE as usize != 0
            || self.max_total_capture_bytes < self.max_window_bytes
            || self.max_total_capture_bytes > mul(self.max_windows, self.max_window_bytes)?
        {
            return Err(refused("initial runtime capture profile differs"));
        }
        geometry::target_stride(self.max_window_bytes)?;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CaptureStage {
    Allocated,
    Original,
    CurrentBinding,
    ExecutableBefore,
    Quarantine,
    Inventory,
    Geometry,
    Window,
    CaptureMapsAfter,
    ExecutableAfter,
    FinalState,
    SnapshotMove,
    Captured,
    RecheckStateBefore,
    RecheckExecutableBefore,
    RecheckMapsBefore,
    RecheckWindow,
    RecheckMapsAfter,
    RecheckExecutableAfter,
    RecheckStateAfter,
    Reauthenticated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CaptureFailureKind {
    Refused(&'static str),
    Invalid(&'static str),
    System {
        operation: &'static str,
        errno: Option<i32>,
        kind: ErrorKind,
    },
    Child(i32),
    Timeout(&'static str),
    Aborted,
    Unexpected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CaptureFailure {
    pub(super) stage: CaptureStage,
    pub(super) window: Option<usize>,
    pub(super) kind: CaptureFailureKind,
}

/// The original EXEC token is historical after bootstrap; it is never passed
/// to a reader again. Kernel entry evidence remains explicitly positive only.
pub(super) struct OriginalBinding {
    pub(super) token: DynamicStop,
    pub(super) entry: EntryEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CurrentBinding {
    pub(super) stop: AdmissionStop,
    pub(super) registers: RegisterSnapshot,
    pub(super) signal_mask: u64,
    // Full bytes live in PreparedInitialSources::xstate, allocated before effects.
    pub(super) xstate_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceWindowId {
    identity: CodeIdentity,
    index: usize,
}
impl SourceWindowId {
    pub(super) fn identity(self) -> CodeIdentity {
        self.identity
    }
    pub(super) fn index(self) -> usize {
        self.index
    }
}

/// Fixed positive evidence; this component never accepts a completeness claim.
/// Root may build a LegalEntrySet only with Partial, this complete Snapshot's
/// exact mapping/generation/scope, and a separately reserved entry allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PartialEntries {
    heads: [Option<u64>; 2],
}
impl PartialEntries {
    pub(super) fn completeness(&self) -> Completeness {
        Completeness::Partial
    }
    pub(super) fn heads(&self) -> impl Iterator<Item = (u64, EntryProvenance)> + '_ {
        self.heads
            .iter()
            .flatten()
            .copied()
            .map(|pc| (pc, EntryProvenance::Loader))
    }
    fn new(scope: AddressRange, entry: &EntryEvidence) -> Self {
        let mut heads = [None, None];
        let a = entry.executable_entry;
        let b = entry.initial_instruction;
        let (first, second) = if a <= b { (a, b) } else { (b, a) };
        if scope.contains(first) {
            heads[0] = Some(first);
        }
        if second != first && scope.contains(second) {
            if heads[0].is_none() {
                heads[0] = Some(second);
            } else {
                heads[1] = Some(second);
            }
        }
        Self { heads }
    }
}

struct WindowStorage {
    id: Option<SourceWindowId>,
    vma: usize,
    geometry: Option<WindowGeometry>,
    bytes: Vec<u8>,
    snapshot: Option<Snapshot>,
    // Snapshot intentionally exposes a slice, not allocator capacity. Preserve
    // the actual transferred capacity here; this is not a second allocation.
    snapshot_capacity: usize,
    entries: PartialEntries,
    capture: SourceReadProgress,
    recheck: SourceReadProgress,
}

pub(super) struct WindowView<'a> {
    pub(super) id: SourceWindowId,
    pub(super) vma: &'a SourceVma,
    pub(super) target: AddressRange,
    pub(super) snapshot: &'a Snapshot,
    pub(super) entries: &'a PartialEntries,
}

/// Non-Clone. Root must install this custody before capture_original and keep
/// it outside a temporarily taken AdmissionOwner through every failure/cleanup.
pub(super) struct PreparedInitialSources {
    authentication: InitialReadScratch,
    storage: InitialSourceStorage,
}

/// Separate fields let the native reader borrow only its authentication
/// scratch while the retained observation storage changes. No Arc or second
/// byte allocation is needed to split those borrows.
struct InitialSourceStorage {
    profile: InitialCaptureProfile,
    until: Instant,
    stage: CaptureStage,
    active_window: Option<usize>,
    failure: Option<CaptureFailure>,
    original: Option<OriginalBinding>,
    current: Option<CurrentBinding>,
    executable: Option<ExecutableIdentity>,
    entry_path: Vec<u8>,
    original_maps: Vec<u8>,
    original_read: SourceReadProgress,
    quarantine_maps: Vec<u8>,
    quarantine_read: SourceReadProgress,
    check_maps: Vec<u8>,
    map_checks: [SourceReadProgress; 3],
    last_map_check: Option<usize>,
    identity_scratch: Vec<u8>,
    byte_scratch: Vec<u8>,
    last_window_check: Option<usize>,
    xstate: Vec<u8>,
    rows: Vec<SourceVma>,
    identities: Vec<CodeIdentity>,
    windows: Vec<WindowStorage>,
    planned: usize,
    original_complete: bool,
    capture_started: bool,
    capture_complete: bool,
    recheck_started: bool,
    recheck_complete: bool,
}

fn refused(reason: &'static str) -> GateError {
    GateError::Refused(reason)
}
fn add(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_add(b)
        .ok_or_else(|| refused("initial runtime allocation size overflows"))
}
fn mul(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_mul(b)
        .ok_or_else(|| refused("initial runtime allocation size overflows"))
}
fn reserve<T>(count: usize) -> Result<Vec<T>, GateError> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(count)
        .map_err(|_| refused("initial runtime allocation failed"))?;
    Ok(storage)
}
fn initialized(count: usize) -> Result<Vec<u8>, GateError> {
    let mut storage = reserve(count)?;
    storage.resize(count, 0);
    Ok(storage)
}

fn require_allocation_peak(retained: usize, reserved: usize) -> Result<(), GateError> {
    // Visible allocation rounding must not consume the separately reserved
    // temporary peak before the first native authentication/read begins.
    if add(retained, super::source_identity::initial_temporary_bytes())? > reserved {
        return Err(refused(
            "initial runtime allocator exceeded its pre-effect bound",
        ));
    }
    Ok(())
}

impl PreparedInitialSources {
    /// Managed allocation upper, not an RSS measurement. Root adds bootstrap,
    /// census/origin, retained catalog and any later report/entry/plan copies.
    /// All other charge dimensions stay zero: no epoch/origin/report is created.
    pub(super) fn reservation_charge(
        profile: InitialCaptureProfile,
    ) -> Result<BudgetCharge, GateError> {
        let profile = profile.validate()?;
        let mut bytes = add(size_of::<Self>(), ENTRY_PATH_BYTES)?;
        bytes = add(bytes, mul(4, MAP_BYTES)?)?;
        bytes = add(bytes, profile.max_window_bytes)?;
        bytes = add(bytes, MAX_XSTATE)?;
        bytes = add(
            bytes,
            mul(
                profile.max_vmas,
                size_of::<SourceVma>() + size_of::<CodeIdentity>(),
            )?,
        )?;
        bytes = add(bytes, mul(profile.max_windows, size_of::<WindowStorage>())?)?;
        bytes = add(bytes, mul(profile.max_windows, profile.max_window_bytes)?)?;
        // The scratch header is already embedded in Self. Its one initialized
        // allocation is independent of retained raw maps/XSTATE/source bytes.
        bytes = add(
            bytes,
            InitialReadScratch::reservation_bytes() - size_of::<InitialReadScratch>(),
        )?;
        // Initial-only fixed authentication/projection requests and the
        // temporary PROT_NONE page are a peak, not retained bytes after cleanup.
        bytes = add(bytes, super::source_identity::initial_temporary_bytes())?;
        Ok(BudgetCharge {
            source_fact_bytes: bytes,
            ..BudgetCharge::default()
        })
    }

    /// Pure allocation only. No initialized observation can be discarded by a
    /// constructor error: native capture begins only after root owns this value.
    pub(super) fn allocate(
        profile: InitialCaptureProfile,
        until: Instant,
    ) -> Result<Self, GateError> {
        let profile = profile.validate()?;
        let bound = Self::reservation_charge(profile)?;
        let result = Self {
            authentication: InitialReadScratch::allocate()?,
            storage: InitialSourceStorage::allocate(profile, until)?,
        };
        require_allocation_peak(result.allocated_bytes()?, bound.source_fact_bytes)?;
        Ok(result)
    }

    pub(super) fn allocated_bytes(&self) -> Result<usize, GateError> {
        // Both inline fields are included once, plus any enclosing alignment
        // padding and all actual owned allocation capacities.
        let inline =
            size_of::<Self>() - size_of::<InitialReadScratch>() - size_of::<InitialSourceStorage>();
        add(
            add(inline, self.authentication.allocated_bytes())?,
            self.storage.allocated_bytes()?,
        )
    }

    pub(super) fn stage(&self) -> CaptureStage {
        self.storage.stage()
    }
    pub(super) fn failure(&self) -> Option<CaptureFailure> {
        self.storage.failure()
    }
    pub(super) fn until(&self) -> Instant {
        self.storage.until()
    }
    pub(super) fn original_binding(&self) -> Option<&OriginalBinding> {
        self.storage.original.as_ref()
    }
    pub(super) fn original_complete(&self) -> bool {
        self.storage.original_complete
    }
    pub(super) fn current_binding(&self) -> Option<&CurrentBinding> {
        self.storage.current_binding()
    }
    pub(super) fn current_xstate(&self) -> Option<&[u8]> {
        self.storage.current_xstate()
    }
    pub(super) fn capture_complete(&self) -> bool {
        self.storage.capture_complete()
    }
    pub(super) fn recheck_complete(&self) -> bool {
        self.storage.recheck_complete()
    }
    pub(super) fn original_maps(&self) -> (&[u8], &SourceReadProgress) {
        self.storage.original_maps()
    }
    pub(super) fn quarantine_maps(&self) -> (&[u8], &SourceReadProgress) {
        self.storage.quarantine_maps()
    }
    pub(super) fn last_maps_check(&self) -> Option<(&[u8], &SourceReadProgress)> {
        self.storage.last_maps_check()
    }
    pub(super) fn window_progress(
        &self,
        index: usize,
    ) -> Option<(&[u8], &SourceReadProgress, &SourceReadProgress)> {
        self.storage.window_progress(index)
    }
    pub(super) fn window(&self, index: usize) -> Option<WindowView<'_>> {
        self.storage.window(index)
    }
    pub(super) fn last_window_check(&self) -> Option<(usize, &[u8], &SourceReadProgress)> {
        self.storage.last_window_check()
    }
    pub(super) fn map_checks(&self) -> &[SourceReadProgress; 3] {
        self.storage.map_checks()
    }
    pub(super) fn window_count(&self) -> usize {
        self.storage.window_count()
    }
    pub(super) fn vmas(&self) -> &[SourceVma] {
        self.storage.vmas()
    }
    pub(super) fn record_aborted(&mut self) {
        self.storage.record_aborted();
    }

    pub(super) fn capture_original(
        &mut self,
        owner: &Owner,
        initial: &DynamicStop,
    ) -> Result<(), GateError> {
        self.storage
            .capture_original(owner, initial, &self.authentication)
    }

    /// # Safety
    /// The caller preserves the existing immutable-source, no-unowned-writer
    /// or alias and singleton bootstrap contract. Ptrace/NX alone does not
    /// establish WriteControl::Owned. No release authority is returned.
    pub(super) unsafe fn capture(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        boot: &BootstrapMm,
    ) -> Result<(), GateError> {
        // SAFETY: the caller supplies the unchanged source ownership contract.
        unsafe {
            self.storage
                .capture(owner, native, boot, &self.authentication)
        }
    }

    pub(super) fn reauthenticate(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        boot: &BootstrapMm,
    ) -> Result<(), GateError> {
        self.storage
            .reauthenticate(owner, native, boot, &self.authentication)
    }
}

impl InitialSourceStorage {
    fn allocate(profile: InitialCaptureProfile, until: Instant) -> Result<Self, GateError> {
        let mut windows = reserve(profile.max_windows)?;
        for _ in 0..profile.max_windows {
            windows.push(WindowStorage {
                id: None,
                vma: 0,
                geometry: None,
                bytes: initialized(profile.max_window_bytes)?,
                snapshot: None,
                snapshot_capacity: 0,
                entries: PartialEntries {
                    heads: [None, None],
                },
                capture: SourceReadProgress::default(),
                recheck: SourceReadProgress::default(),
            });
        }
        let result = Self {
            profile,
            until,
            stage: CaptureStage::Allocated,
            active_window: None,
            failure: None,
            original: None,
            current: None,
            executable: None,
            entry_path: initialized(ENTRY_PATH_BYTES)?,
            original_maps: initialized(MAP_BYTES)?,
            original_read: SourceReadProgress::default(),
            quarantine_maps: initialized(MAP_BYTES)?,
            quarantine_read: SourceReadProgress::default(),
            check_maps: initialized(MAP_BYTES)?,
            map_checks: std::array::from_fn(|_| SourceReadProgress::default()),
            last_map_check: None,
            identity_scratch: initialized(MAP_BYTES)?,
            byte_scratch: initialized(profile.max_window_bytes)?,
            last_window_check: None,
            xstate: initialized(MAX_XSTATE)?,
            rows: reserve(profile.max_vmas)?,
            identities: reserve(profile.max_vmas)?,
            windows,
            planned: 0,
            original_complete: false,
            capture_started: false,
            capture_complete: false,
            recheck_started: false,
            recheck_complete: false,
        };
        Ok(result)
    }

    pub(super) fn allocated_bytes(&self) -> Result<usize, GateError> {
        let mut bytes = size_of::<Self>();
        for buffer in [
            &self.entry_path,
            &self.original_maps,
            &self.quarantine_maps,
            &self.check_maps,
            &self.identity_scratch,
            &self.byte_scratch,
            &self.xstate,
        ] {
            bytes = add(bytes, buffer.capacity())?;
        }
        bytes = add(bytes, mul(self.rows.capacity(), size_of::<SourceVma>())?)?;
        bytes = add(
            bytes,
            mul(self.identities.capacity(), size_of::<CodeIdentity>())?,
        )?;
        bytes = add(
            bytes,
            mul(self.windows.capacity(), size_of::<WindowStorage>())?,
        )?;
        for window in &self.windows {
            bytes = add(bytes, window.bytes.capacity())?;
            bytes = add(bytes, window.snapshot_capacity)?;
        }
        if let Some(original) = &self.original {
            bytes = add(
                bytes,
                original
                    .entry
                    .interpreter
                    .as_ref()
                    .map_or(0, |path| path.capacity()),
            )?;
        }
        Ok(bytes)
    }

    pub(super) fn stage(&self) -> CaptureStage {
        self.stage
    }
    pub(super) fn failure(&self) -> Option<CaptureFailure> {
        self.failure
    }
    pub(super) fn until(&self) -> Instant {
        self.until
    }
    pub(super) fn current_binding(&self) -> Option<&CurrentBinding> {
        self.current.as_ref()
    }
    pub(super) fn current_xstate(&self) -> Option<&[u8]> {
        self.current
            .as_ref()
            .map(|binding| &self.xstate[..binding.xstate_len])
    }
    pub(super) fn capture_complete(&self) -> bool {
        self.capture_complete
    }
    pub(super) fn recheck_complete(&self) -> bool {
        self.recheck_complete
    }
    pub(super) fn original_maps(&self) -> (&[u8], &SourceReadProgress) {
        (&self.original_maps, &self.original_read)
    }
    pub(super) fn quarantine_maps(&self) -> (&[u8], &SourceReadProgress) {
        (&self.quarantine_maps, &self.quarantine_read)
    }
    pub(super) fn last_maps_check(&self) -> Option<(&[u8], &SourceReadProgress)> {
        self.last_map_check
            .map(|index| (self.check_maps.as_slice(), &self.map_checks[index]))
    }
    /// Includes initialized unobserved suffix. Progress distinguishes that
    /// substrate from bytes actually copied before a short/error/unwind.
    pub(super) fn window_progress(
        &self,
        index: usize,
    ) -> Option<(&[u8], &SourceReadProgress, &SourceReadProgress)> {
        self.windows
            .get(index)
            .filter(|_| index < self.planned)
            .map(|slot| {
                let bytes = slot
                    .snapshot
                    .as_ref()
                    .map_or(slot.bytes.as_slice(), Snapshot::bytes);
                (bytes, &slot.capture, &slot.recheck)
            })
    }
    pub(super) fn window(&self, index: usize) -> Option<WindowView<'_>> {
        if !self.capture_complete {
            return None;
        }
        let slot = self.windows.get(index).filter(|_| index < self.planned)?;
        Some(WindowView {
            id: slot.id?,
            vma: self.rows.get(slot.vma)?,
            target: slot.geometry?.target,
            snapshot: slot.snapshot.as_ref()?,
            entries: &slot.entries,
        })
    }
    pub(super) fn last_window_check(&self) -> Option<(usize, &[u8], &SourceReadProgress)> {
        self.last_window_check.map(|index| {
            (
                index,
                self.byte_scratch.as_slice(),
                &self.windows[index].recheck,
            )
        })
    }
    pub(super) fn map_checks(&self) -> &[SourceReadProgress; 3] {
        &self.map_checks
    }
    pub(super) fn window_count(&self) -> usize {
        self.planned
    }
    pub(super) fn vmas(&self) -> &[SourceVma] {
        &self.rows
    }

    /// Root calls this only for an actual abandoned/unwound transaction. It
    /// changes diagnostic status only and makes no physical-cleanup claim.
    pub(super) fn record_aborted(&mut self) {
        if self.failure.is_none() && !self.recheck_complete {
            self.failure = Some(CaptureFailure {
                stage: self.stage,
                window: self.active_window,
                kind: CaptureFailureKind::Aborted,
            });
        }
    }
    fn retain_error(&mut self, result: &Result<(), GateError>) {
        if self.failure.is_some() {
            return;
        }
        if let Err(error) = result {
            let kind = match error {
                GateError::Refused(reason) => CaptureFailureKind::Refused(reason),
                GateError::Control(LaunchError::Invalid(reason)) => {
                    CaptureFailureKind::Invalid(reason)
                }
                GateError::Control(LaunchError::System { operation, source }) => {
                    CaptureFailureKind::System {
                        operation,
                        errno: source.raw_os_error(),
                        kind: source.kind(),
                    }
                }
                GateError::Control(LaunchError::Child { status }) => {
                    CaptureFailureKind::Child(*status)
                }
                GateError::Control(LaunchError::Timeout(reason)) => {
                    CaptureFailureKind::Timeout(reason)
                }
                _ => CaptureFailureKind::Unexpected,
            };
            self.failure = Some(CaptureFailure {
                stage: self.stage,
                window: self.active_window,
                kind,
            });
        }
    }
}

impl InitialSourceStorage {
    /// Read-only preflight while initial is still the genuine original EXEC.
    /// A failed read retains its initialized map prefix in this same object.
    fn capture_original(
        &mut self,
        owner: &Owner,
        initial: &DynamicStop,
        authentication: &InitialReadScratch,
    ) -> Result<(), GateError> {
        let result = (|| {
            if self.stage != CaptureStage::Allocated
                || self.original.is_some()
                || self.failure.is_some()
            {
                return Err(refused("initial runtime original capture was already used"));
            }
            self.stage = CaptureStage::Original;
            let reader = OriginalSourceRead::acquire(owner, initial, self.until, authentication)?;
            let event = owner.require_stop(initial)?;
            let DynamicEventKind::Exec { evidence } = &event.kind else {
                return Err(refused(
                    "initial runtime lacks actual initial EXEC evidence",
                ));
            };
            let entry = retain_entry(evidence, &mut self.entry_path)?;
            self.original = Some(OriginalBinding {
                token: initial.clone(),
                entry,
            });
            reader.read_maps_capture(&mut self.original_maps, &mut self.original_read)?;
            observed_maps(&self.original_maps, &self.original_read)?;
            self.check_allocation()?;
            self.original_complete = true;
            Ok(())
        })();
        self.retain_error(&result);
        result
    }

    /// # Safety
    /// Root's runtime constructor retains the existing immutable source,
    /// no-unowned-writer/alias and singleton bootstrap contract. Held ptrace/NX
    /// alone does not prove WriteControl::Owned against external writers.
    /// This method supplies bytes/Partial evidence only, never release authority.
    pub(super) unsafe fn capture(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        boot: &BootstrapMm,
        authentication: &InitialReadScratch,
    ) -> Result<(), GateError> {
        let result = (|| {
            if !self.original_complete || self.capture_started || self.failure.is_some() {
                return Err(refused(
                    "initial runtime capture is not a fresh prepared transaction",
                ));
            }
            self.capture_started = true;
            self.stage = CaptureStage::CurrentBinding;
            let reader =
                HeldSourceRead::acquire_initial(owner, native, boot, self.until, authentication)?;
            let original = self
                .original
                .as_ref()
                .ok_or_else(|| refused("initial runtime original evidence is absent"))?;
            // Different task-token domains need no invented cross-domain
            // sequence comparison. Both endpoints have their own real proof.
            if original.token.session != boot.stop.token.session
                || original.token.tid != boot.stop.token.tid
                || boot.stop.identity.generation != 0
                || boot.evidence.restored_entry.registers.rip != original.entry.initial_instruction
            {
                return Err(refused(
                    "initial runtime bootstrap belongs to another launch",
                ));
            }
            let raw = &boot.evidence.restored_entry;
            if !(512..MAX_XSTATE).contains(&raw.xstate.len())
                || raw.xstate.len() > self.xstate.len()
            {
                return Err(refused("initial runtime complete state extent differs"));
            }
            self.xstate[..raw.xstate.len()].copy_from_slice(&raw.xstate);
            self.current = Some(CurrentBinding {
                stop: boot.stop.clone(),
                registers: raw.registers,
                signal_mask: raw.mask,
                xstate_len: raw.xstate.len(),
            });
            self.stage = CaptureStage::ExecutableBefore;
            let executable = reader.executable_projection(&mut self.identity_scratch)?;
            self.executable = Some(executable);
            self.stage = CaptureStage::Quarantine;
            reader.read_maps_capture(&mut self.quarantine_maps, &mut self.quarantine_read)?;
            self.stage = CaptureStage::Inventory;
            SourceInventory::validate(
                observed_maps(&self.original_maps, &self.original_read)?,
                observed_maps(&self.quarantine_maps, &self.quarantine_read)?,
                boot,
                &original.entry,
                executable.vma,
                &mut self.rows,
                self.profile.max_vmas,
            )?;
            self.stage = CaptureStage::Geometry;
            self.plan_windows()?;
            for index in 0..self.planned {
                self.stage = CaptureStage::Window;
                self.active_window = Some(index);
                let slot = &mut self.windows[index];
                let geometry = slot.geometry.expect("planned window geometry");
                let len = extent(geometry.snapshot)?;
                reader.read_memory_into(
                    geometry.snapshot.start(),
                    &mut slot.bytes[..len],
                    &mut slot.capture,
                )?;
                require_complete_read(&slot.capture, len)?;
                validate_heads(&slot.bytes[..len], geometry, &slot.entries)?;
            }
            self.active_window = None;
            self.stage = CaptureStage::CaptureMapsAfter;
            self.compare_current_maps(&reader, 0)?;
            self.stage = CaptureStage::ExecutableAfter;
            if reader.executable_projection(&mut self.identity_scratch)? != executable {
                return Err(refused(
                    "initial runtime executable projection changed during capture",
                ));
            }
            self.stage = CaptureStage::FinalState;
            reader.reauthenticate()?;
            self.verify_binding(boot)?;
            self.check_allocation()?;
            self.stage = CaptureStage::SnapshotMove;
            // All fallible native/geometry/decode checks precede these moves.
            self.move_snapshots();
            self.capture_complete = true;
            self.stage = CaptureStage::Captured;
            Ok(())
        })();
        self.retain_error(&result);
        result
    }

    /// One read-only post-advisor/commit reauthentication under the SAME stop
    /// and absolute deadline. No native operation may occur between bootstrap
    /// and this call. Root retains the actual BootstrapMm and lifecycle owner.
    pub(super) fn reauthenticate(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        boot: &BootstrapMm,
        authentication: &InitialReadScratch,
    ) -> Result<(), GateError> {
        let result = (|| {
            if !self.capture_complete || self.recheck_started || self.failure.is_some() {
                return Err(refused(
                    "initial runtime recheck is not a fresh captured transaction",
                ));
            }
            self.recheck_started = true;
            self.stage = CaptureStage::RecheckStateBefore;
            self.verify_binding(boot)?;
            let reader =
                HeldSourceRead::acquire_initial(owner, native, boot, self.until, authentication)?;
            self.stage = CaptureStage::RecheckExecutableBefore;
            if Some(reader.executable_projection(&mut self.identity_scratch)?) != self.executable {
                return Err(refused(
                    "initial runtime executable projection differs before recheck",
                ));
            }
            self.stage = CaptureStage::RecheckMapsBefore;
            self.compare_current_maps(&reader, 1)?;
            for index in 0..self.planned {
                self.stage = CaptureStage::RecheckWindow;
                self.active_window = Some(index);
                let slot = &mut self.windows[index];
                let geometry = slot
                    .geometry
                    .ok_or_else(|| refused("initial runtime retained geometry is absent"))?;
                let snapshot = slot
                    .snapshot
                    .as_ref()
                    .ok_or_else(|| refused("initial runtime retained snapshot is absent"))?;
                verify_window(slot, &self.identities, index)?;
                let len = snapshot.bytes().len();
                self.byte_scratch.fill(0);
                self.last_window_check = Some(index);
                reader.read_memory_into(
                    snapshot.range().start(),
                    &mut self.byte_scratch[..len],
                    &mut slot.recheck,
                )?;
                require_complete_read(&slot.recheck, len)?;
                verify_window_bytes(snapshot, &self.byte_scratch[..len])?;
                validate_heads(snapshot.bytes(), geometry, &slot.entries)?;
            }
            self.active_window = None;
            self.stage = CaptureStage::RecheckMapsAfter;
            self.compare_current_maps(&reader, 2)?;
            self.stage = CaptureStage::RecheckExecutableAfter;
            if Some(reader.executable_projection(&mut self.identity_scratch)?) != self.executable {
                return Err(refused(
                    "initial runtime executable projection changed during recheck",
                ));
            }
            self.stage = CaptureStage::RecheckStateAfter;
            reader.reauthenticate()?;
            self.verify_binding(boot)?;
            self.check_allocation()?;
            self.recheck_complete = true;
            self.stage = CaptureStage::Reauthenticated;
            Ok(())
        })();
        self.retain_error(&result);
        result
    }

    fn move_snapshots(&mut self) {
        for index in 0..self.planned {
            let slot = &mut self.windows[index];
            let geometry = slot.geometry.expect("validated window geometry");
            let id = slot.id.expect("validated window identity");
            let mut bytes = std::mem::take(&mut slot.bytes);
            bytes.truncate((geometry.snapshot.end() - geometry.snapshot.start()) as usize);
            slot.snapshot_capacity = bytes.capacity();
            slot.snapshot = Some(
                Snapshot::new(
                    MappingId(id.identity.mapping),
                    Generation(id.identity.generation),
                    geometry.snapshot.start(),
                    bytes,
                    geometry.before,
                    geometry.after,
                    WriteControl::Owned,
                )
                .expect("validated nonempty snapshot range"),
            );
        }
    }
    fn verify_binding(&self, boot: &BootstrapMm) -> Result<(), GateError> {
        let binding = self
            .current
            .as_ref()
            .ok_or_else(|| refused("initial runtime current binding is absent"))?;
        let raw = &boot.evidence.restored_entry;
        if binding.stop != boot.stop
            || binding.registers != raw.registers
            || binding.signal_mask != raw.mask
            || binding.xstate_len != raw.xstate.len()
            || self.xstate[..binding.xstate_len] != raw.xstate
        {
            return Err(refused(
                "initial runtime current complete state binding differs",
            ));
        }
        Ok(())
    }
    fn compare_current_maps(
        &mut self,
        reader: &HeldSourceRead<'_>,
        index: usize,
    ) -> Result<(), GateError> {
        self.last_map_check = Some(index);
        reader.read_maps_capture(&mut self.check_maps, &mut self.map_checks[index])?;
        if observed_maps(&self.check_maps, &self.map_checks[index])?
            != observed_maps(&self.quarantine_maps, &self.quarantine_read)?
        {
            return Err(refused(
                "initial runtime complete current map inventory changed",
            ));
        }
        Ok(())
    }
    fn check_allocation(&self) -> Result<(), GateError> {
        let payload_bound = PreparedInitialSources::reservation_charge(self.profile)?
            .source_fact_bytes
            - size_of::<PreparedInitialSources>()
            + size_of::<Self>()
            - (InitialReadScratch::reservation_bytes() - size_of::<InitialReadScratch>())
            - super::source_identity::initial_temporary_bytes();
        if self.allocated_bytes()? > payload_bound {
            return Err(refused(
                "initial runtime retained allocation exceeded its reservation",
            ));
        }
        Ok(())
    }
    fn plan_windows(&mut self) -> Result<(), GateError> {
        if self.planned != 0 || !self.identities.is_empty() || self.rows.is_empty() {
            return Err(refused("initial runtime window plan was already used"));
        }
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| refused("initial runtime original evidence is absent"))?;
        let old = observed_maps(&self.original_maps, &self.original_read)?;
        let new = observed_maps(&self.quarantine_maps, &self.quarantine_read)?;
        let stride = geometry::target_stride(self.profile.max_window_bytes)?;
        let mut total = 0;
        for (vma_index, row) in self.rows.iter().enumerate() {
            let view = row.view(old, new)?;
            let before = if view
                .lower_original
                .is_some_and(|neighbor| neighbor.permissions.bytes()[2] == b'x')
            {
                Boundary::Unknown
            } else {
                Boundary::NonExecutable
            };
            let after = if view
                .upper_original
                .is_some_and(|neighbor| neighbor.permissions.bytes()[2] == b'x')
            {
                Boundary::Unknown
            } else {
                Boundary::NonExecutable
            };
            let range = AddressRange::new(row.start, row.end)
                .ok_or_else(|| refused("initial runtime VMA range differs"))?;
            let vma = VmaGeometry {
                range,
                before,
                after,
            };
            let identity = crate::gate::domain::new_core_identity()?;
            self.identities.push(identity);
            let mut start = range.start();
            while start < range.end() {
                if self.planned == self.profile.max_windows {
                    return Err(refused("initial runtime window count exceeds its bound"));
                }
                let target = geometry::next_target(range, start, stride)?;
                let geometry =
                    WindowGeometry::for_target(vma, target, self.profile.max_window_bytes)?;
                total = add(total, extent(geometry.snapshot)?)?;
                if total > self.profile.max_total_capture_bytes {
                    return Err(refused(
                        "initial runtime overlapping capture bytes exceed their bound",
                    ));
                }
                let slot = &mut self.windows[self.planned];
                slot.id = Some(SourceWindowId {
                    identity,
                    index: self.planned,
                });
                slot.vma = vma_index;
                slot.geometry = Some(geometry);
                slot.entries = PartialEntries::new(geometry.head_scope, &original.entry);
                self.planned += 1;
                start = target.end();
            }
        }
        if !self.windows[..self.planned].iter().any(|slot| {
            slot.geometry.is_some_and(|geometry| {
                geometry.target.contains(original.entry.initial_instruction)
            })
        }) {
            return Err(refused(
                "initial runtime first instruction lacks a complete source window",
            ));
        }
        Ok(())
    }
}

fn extent(range: AddressRange) -> Result<usize, GateError> {
    usize::try_from(range.end() - range.start())
        .map_err(|_| refused("initial runtime byte extent overflows"))
}
fn retain_entry(
    evidence: &EntryEvidence,
    storage: &mut Vec<u8>,
) -> Result<EntryEvidence, GateError> {
    let interpreter = if let Some(path) = &evidence.interpreter {
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() > ENTRY_PATH_BYTES || storage.capacity() < bytes.len() {
            return Err(refused("initial runtime entry path exceeds its bound"));
        }
        // Move the already reserved byte allocation through the Unix owned
        // string/path representations. No clone or post-effect growth occurs.
        let mut owned = std::mem::take(storage);
        owned.clear();
        owned.extend_from_slice(bytes);
        Some(std::path::PathBuf::from(std::ffi::OsString::from_vec(
            owned,
        )))
    } else {
        None
    };
    Ok(EntryEvidence {
        first_image: evidence.first_image,
        executable_entry: evidence.executable_entry,
        interpreter_base: evidence.interpreter_base,
        initial_instruction: evidence.initial_instruction,
        interpreter,
    })
}
fn require_complete_read(progress: &SourceReadProgress, count: usize) -> Result<(), GateError> {
    if !progress.started
        || !progress.attempted
        || !progress.complete
        || progress.failure.is_some()
        || progress.requested_bytes != count
        || progress.copied_bytes != count
    {
        return Err(refused("initial runtime byte read is incomplete"));
    }
    Ok(())
}
fn observed_maps<'a>(
    bytes: &'a [u8],
    progress: &SourceReadProgress,
) -> Result<&'a [u8], GateError> {
    if !progress.started
        || !progress.attempted
        || !progress.complete
        || progress.failure.is_some()
        || progress.copied_bytes == 0
        || progress.copied_bytes > bytes.len()
        || progress.filesystem_type != Some(libc::PROC_SUPER_MAGIC)
        || progress.requested_bytes != bytes.len()
    {
        return Err(refused(
            "initial runtime complete raw map capture is absent",
        ));
    }
    Ok(&bytes[..progress.copied_bytes])
}
fn validate_heads(
    bytes: &[u8],
    geometry: WindowGeometry,
    entries: &PartialEntries,
) -> Result<(), GateError> {
    if bytes.len() != extent(geometry.snapshot)? {
        return Err(refused(
            "initial runtime full dependency bytes are incomplete",
        ));
    }
    for (pc, _) in entries.heads() {
        if !geometry.head_scope.contains(pc) || !geometry.snapshot.contains(pc) {
            return Err(refused(
                "initial runtime positive entry is outside its dependency",
            ));
        }
        let offset = usize::try_from(pc - geometry.snapshot.start())
            .map_err(|_| refused("initial runtime entry offset overflows"))?;
        let instruction = Decoder::with_ip(64, &bytes[offset..], pc, DecoderOptions::NONE).decode();
        if instruction.is_invalid()
            || instruction.len() == 0
            || instruction.next_ip() <= pc
            || instruction.next_ip() > geometry.snapshot.end()
        {
            return Err(refused(
                "initial runtime positive entry lacks a complete native64 decode",
            ));
        }
    }
    Ok(())
}

fn verify_window(
    slot: &WindowStorage,
    identities: &[CodeIdentity],
    index: usize,
) -> Result<(), GateError> {
    let snapshot = slot
        .snapshot
        .as_ref()
        .ok_or_else(|| refused("initial runtime retained snapshot is absent"))?;
    let id = slot
        .id
        .ok_or_else(|| refused("initial runtime retained identity is absent"))?;
    let identity = id.identity;
    if id.index != index
        || snapshot.mapping != MappingId(identity.mapping)
        || snapshot.generation != Generation(identity.generation)
        || identities.get(slot.vma) != Some(&identity)
    {
        return Err(refused("initial runtime retained source identity differs"));
    }
    slot.geometry
        .ok_or_else(|| refused("initial runtime retained geometry is absent"))?
        .validate_snapshot(snapshot)
}

fn verify_window_bytes(snapshot: &Snapshot, actual: &[u8]) -> Result<(), GateError> {
    if actual != snapshot.bytes() {
        return Err(refused("initial runtime original window bytes changed"));
    }
    Ok(())
}
