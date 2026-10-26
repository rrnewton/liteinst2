//! Separate pair-selected startup path. Preflight uses already prepaid window
//! slots, with no source identities. Its exact geometry survives every failure.
use super::super::initial_coalescence::InitialMapPlan;
use super::super::mapping::maps::{MapEntry, ParsedMaps};
use super::super::source_identity::FileIdentity;
use super::*;

const PAIR_CAPTURE_BYTES: usize = 2 * 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct InitialWindowSizing {
    windows: usize,
    vmas: usize,
    window_bytes: usize,
}
impl InitialWindowSizing {
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn window_bytes(self) -> usize {
        self.window_bytes
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn pair_capture_bytes(self) -> usize {
        PAIR_CAPTURE_BYTES
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn total_capture_bytes(
        self,
    ) -> Result<usize, GateError> {
        add(self.window_bytes, self.pair_capture_bytes())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OriginalWindowWitness {
    original_index: usize,
    original_span: (usize, usize),
    lower_span: Option<(usize, usize)>,
    upper_span: Option<(usize, usize)>,
    offset: u64,
    file: FileIdentity,
    geometry: VmaGeometry,
}
fn span(raw: &[u8], row: MapEntry<'_>) -> (usize, usize) {
    (
        row.raw_line.as_ptr() as usize - raw.as_ptr() as usize,
        row.raw_line.len(),
    )
}
fn witness(
    maps: ParsedMaps<'_>,
    index: usize,
    row: MapEntry<'_>,
) -> Result<OriginalWindowWitness, GateError> {
    let lower = index
        .checked_sub(1)
        .and_then(|i| maps.entries().nth(i))
        .filter(|a| a.end == row.start);
    let upper = maps.entries().nth(index + 1).filter(|a| a.start == row.end);
    let boundary = |neighbor: Option<MapEntry<'_>>| {
        if neighbor.is_some_and(|a| a.permissions.bytes()[2] == b'x') {
            Boundary::Unknown
        } else {
            Boundary::NonExecutable
        }
    };
    Ok(OriginalWindowWitness {
        original_index: index,
        original_span: span(maps.raw(), row),
        lower_span: lower.map(|a| span(maps.raw(), a)),
        upper_span: upper.map(|a| span(maps.raw(), a)),
        offset: row.file_offset,
        file: FileIdentity {
            major: row.device_major,
            minor: row.device_minor,
            inode: row.inode,
        },
        geometry: VmaGeometry {
            range: AddressRange::new(row.start, row.end)
                .ok_or_else(|| refused("initial runtime VMA range differs"))?,
            before: boundary(lower),
            after: boundary(upper),
        },
    })
}

/// Both preflight and authenticated capture use this exact closure calculation.
/// Every overlap, target+28 trailing head dependency, and original executable
/// neighbour is included before the pair's extra captures are added.
fn walk_windows(
    original: &InitialOriginalInventory<'_>,
    entry: &EntryEvidence,
    profile: InitialCaptureProfile,
    mut accept: impl FnMut(
        usize,
        usize,
        OriginalWindowWitness,
        WindowGeometry,
        PartialEntries,
    ) -> Result<(), GateError>,
) -> Result<InitialWindowSizing, GateError> {
    let profile = profile.validate()?;
    let stride = geometry::target_stride(profile.max_window_bytes)?;
    let mut sizing = InitialWindowSizing {
        windows: 0,
        vmas: 0,
        window_bytes: 0,
    };
    let mut contains_entry = false;
    for (index, row) in original.originals().entries().enumerate() {
        if !original.eligible(row) {
            continue;
        }
        let row = original.source(index)?;
        if sizing.vmas == profile.max_vmas {
            return Err(refused("initial source VMA inventory exceeds its bound"));
        }
        let witness = witness(original.originals(), index, row)?;
        let mut start = witness.geometry.range.start();
        while start < witness.geometry.range.end() {
            if sizing.windows == profile.max_windows {
                return Err(refused("initial runtime window count exceeds its bound"));
            }
            let target = geometry::next_target(witness.geometry.range, start, stride)?;
            let geometry =
                WindowGeometry::for_target(witness.geometry, target, profile.max_window_bytes)?;
            sizing.window_bytes = add(sizing.window_bytes, extent(geometry.snapshot)?)?;
            if sizing.total_capture_bytes()? > profile.max_total_capture_bytes {
                return Err(refused(
                    "initial runtime pair and overlapping capture bytes exceed their bound",
                ));
            }
            let entries = PartialEntries::new(geometry.head_scope, entry);
            accept(sizing.windows, sizing.vmas, witness, geometry, entries)?;
            contains_entry |= geometry.target.contains(entry.initial_instruction);
            sizing.windows += 1;
            start = target.end();
        }
        sizing.vmas += 1;
    }
    if sizing.vmas == 0 || !contains_entry {
        return Err(refused(
            "initial runtime first instruction lacks a complete source window",
        ));
    }
    Ok(sizing)
}

impl PreparedInitialSources {
    pub(in crate::linux::remote::dynamic::owner::admission) fn initial_scratch(
        &self,
    ) -> &InitialReadScratch {
        &self.authentication
    }

    /// Fixed descriptive views live only during pure preflight/authenticated
    /// comparison. Native reader/complete-map projection peak is separate.
    pub(in crate::linux::remote::dynamic::owner::admission) fn coalescence_temporary_bytes() -> usize
    {
        2 * size_of::<InitialOriginalInventory<'_>>()
            + 2 * size_of::<OriginalWindowWitness>()
            + 2 * size_of::<WindowGeometry>()
            + 2 * size_of::<VmaGeometry>()
            + 2 * size_of::<PartialEntries>()
            + 2 * size_of::<InitialWindowSizing>()
            + size_of::<super::super::source_identity::InitialSourceValidation<'_>>()
            + 2 * size_of::<InitialSourceVma>()
            + 2 * size_of::<ExecutableIdentity>()
            + InitialMapPlan::temporary_bytes()
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn coalescence_payload_reservation(
        profile: InitialCaptureProfile,
    ) -> Result<usize, GateError> {
        let profile = profile.validate()?;
        mul(profile.max_vmas, size_of::<InitialSourceVma>())
    }

    /// Root reserves the additional payload first. The exact allocation is
    /// installed immediately; failure/unwind never replaces this prepared owner.
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocate_coalescence_payloads(
        &mut self,
    ) -> Result<(), GateError> {
        let result = (|| {
            if self.storage.initial_rows.capacity() != 0
                || self.storage.capture_started
                || (self.storage.preflight_started && self.storage.preflight_sizing.is_none())
                || self.storage.failure.is_some()
            {
                return Err(refused(
                    "initial coalescence payload storage was already used",
                ));
            }
            let count = self.storage.profile.max_vmas;
            Self::coalescence_payload_reservation(self.storage.profile)?;
            let layout = std::alloc::Layout::array::<InitialSourceVma>(count)
                .map_err(|_| refused("initial coalescence payload layout overflows"))?;
            // SAFETY: positive validated count and nonzero T; exact global
            // allocation/alignment. No values are initialized or exposed yet.
            let pointer = unsafe { std::alloc::alloc(layout) }.cast::<InitialSourceVma>();
            if pointer.is_null() {
                return Err(refused("initial coalescence payload allocation failed"));
            }
            // SAFETY: unique allocation, len0, exact checked capacity/layout;
            // Vec drops only later initialized rows and frees this same layout.
            self.storage.initial_rows = unsafe { Vec::from_raw_parts(pointer, 0, count) };
            self.storage.check_allocation()
        })();
        self.storage.retain_error(&result);
        result
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn coalescence_plan(
        &mut self,
        owner: &Owner,
        initial: &DynamicStop,
    ) -> Result<Option<(InitialMapPlan, ExecutableIdentity)>, GateError> {
        let mut selected = None;
        let result = (|| {
            if !self.storage.original_complete
                || self.storage.capture_started
                || self.storage.failure.is_some()
            {
                return Err(refused("initial coalescence plan lacks original capture"));
            }
            let original = self
                .storage
                .original
                .as_ref()
                .ok_or_else(|| refused("initial runtime original evidence is absent"))?;
            if &original.token != initial {
                return Err(refused("initial coalescence original stop differs"));
            }
            let reader = OriginalSourceRead::acquire(
                owner,
                initial,
                self.storage.until,
                &self.authentication,
            )?;
            if self.storage.coalescence_check_count == self.storage.coalescence_checks.len() {
                return Err(refused(
                    "initial coalescence original map checks were already used",
                ));
            }
            let index = self.storage.coalescence_check_count;
            self.storage.coalescence_check_count += 1;
            reader.read_maps_capture(
                &mut self.storage.check_maps,
                &mut self.storage.coalescence_checks[index],
            )?;
            if observed_maps(
                &self.storage.check_maps,
                &self.storage.coalescence_checks[index],
            )? != observed_maps(&self.storage.original_maps, &self.storage.original_read)?
            {
                return Err(refused(
                    "initial coalescence original complete map inventory differs",
                ));
            }
            let executable = reader.executable_projection(&mut self.storage.identity_scratch)?;
            let plan = InitialMapPlan::select(
                observed_maps(&self.storage.original_maps, &self.storage.original_read)?,
                &original.entry,
                (
                    executable.vma.major,
                    executable.vma.minor,
                    executable.vma.inode,
                ),
            )?;
            selected = Some(plan.map(|plan| (plan, executable)));
            Ok(())
        })();
        self.storage.retain_error(&result);
        result?;
        selected.ok_or_else(|| refused("initial coalescence selection result is absent"))
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn capture_coalescence_original(
        &mut self,
        owner: &Owner,
        initial: &DynamicStop,
        plan: &InitialMapPlan,
        storage: &mut [u8],
        progress: &mut SourceReadProgress,
    ) -> Result<(), GateError> {
        let Some((actual, executable)) = self.coalescence_plan(owner, initial)? else {
            return Err(refused("initial coalescence original pair is absent"));
        };
        if actual != *plan
            || self.storage.preflight_plan.as_ref() != Some(plan)
            || self.storage.preflight_executable != Some(executable)
            || self.storage.preflight_sizing.is_none()
            || self.storage.initial_rows.capacity() != self.storage.profile.max_vmas
            || plan.pair_range().end - plan.pair_range().start != 8192
            || storage.len() != 8192
        {
            return Err(refused("initial coalescence original pair capture differs"));
        }
        let reader =
            OriginalSourceRead::acquire(owner, initial, self.storage.until, &self.authentication)?;
        reader.read_memory_capture(plan.pair_range().start, storage, progress)
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn preflight_coalesced(
        &mut self,
        plan: &InitialMapPlan,
        executable: ExecutableIdentity,
    ) -> Result<InitialWindowSizing, GateError> {
        let mut sizing = None;
        let result = (|| {
            sizing = Some(self.storage.preflight_coalesced(plan, executable)?);
            Ok(())
        })();
        self.storage.retain_error(&result);
        result?;
        sizing.ok_or_else(|| refused("initial coalescence preflight sizing is absent"))
    }

    /// # Safety
    /// Same immutable-source/no-unowned-writer contract as capture(). The
    /// borrowed completed native producer additionally proves the finite pair.
    pub(in crate::linux::remote::dynamic::owner::admission) unsafe fn capture_coalesced(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        boot: &BootstrapMm,
        completed: &CompletedInitialCoalescence<'_>,
    ) -> Result<(), GateError> {
        // SAFETY: forwarded unchanged source ownership contract and sealed
        // completed native bootstrap proof; neither is supplied by preflight.
        unsafe {
            self.storage
                .capture_inner(owner, native, boot, &self.authentication, Some(completed))
        }
    }
}

impl InitialSourceStorage {
    fn preflight_coalesced(
        &mut self,
        plan: &InitialMapPlan,
        executable: ExecutableIdentity,
    ) -> Result<InitialWindowSizing, GateError> {
        if !self.original_complete
            || self.capture_started
            || self.preflight_started
            || self.failure.is_some()
            || (self.initial_rows.capacity() != 0
                && self.initial_rows.capacity() != self.profile.max_vmas)
            || self.planned != 0
            || !self.identities.is_empty()
        {
            return Err(refused("initial coalescence preflight is not fresh"));
        }
        self.preflight_started = true;
        self.stage = CaptureStage::CoalescencePreflight;
        self.preflight_plan = Some(*plan);
        self.preflight_executable = Some(executable);
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| refused("initial runtime original evidence is absent"))?;
        let inventory = InitialOriginalInventory::new(
            observed_maps(&self.original_maps, &self.original_read)?,
            &original.entry,
            executable.vma,
            plan,
        )?;
        let sizing = walk_windows(
            &inventory,
            &original.entry,
            self.profile,
            |index, vma, witness, geometry, entries| {
                let slot = &mut self.windows[index];
                if slot.id.is_some() || slot.snapshot.is_some() || slot.geometry.is_some() {
                    return Err(refused(
                        "initial coalescence preflight window was already used",
                    ));
                }
                slot.vma = vma;
                slot.original_witness = Some(witness);
                slot.geometry = Some(geometry);
                slot.entries = entries;
                self.preflight_filled = index + 1;
                Ok(())
            },
        )?;
        self.preflight_sizing = Some(sizing);
        self.check_allocation()?;
        Ok(sizing)
    }

    pub(super) fn require_coalesced_completion(
        &self,
        completed: &CompletedInitialCoalescence<'_>,
        boot: &BootstrapMm,
        executable: ExecutableIdentity,
    ) -> Result<(), GateError> {
        if self.preflight_plan.as_ref() != Some(completed.projection().plan())
            || self.preflight_executable != Some(executable)
            || self.preflight_sizing.is_none()
            || completed.until() != self.until
            || completed.final_stop() != &boot.stop
            || completed.original_maps(observed_maps(&self.original_maps, &self.original_read)?)?
                != observed_maps(&self.original_maps, &self.original_read)?
            || completed.final_maps()
                != observed_maps(&self.quarantine_maps, &self.quarantine_read)?
        {
            return Err(refused(
                "initial coalescence completed source binding differs",
            ));
        }
        Ok(())
    }

    pub(super) fn plan_coalesced_windows(
        &mut self,
        executable: ExecutableIdentity,
    ) -> Result<(), GateError> {
        if self.planned != 0
            || !self.identities.is_empty()
            || self.rows.is_empty()
            || self.rows.len() != self.initial_rows.len()
        {
            return Err(refused(
                "initial coalescence authenticated window plan was already used",
            ));
        }
        let plan = self
            .preflight_plan
            .as_ref()
            .ok_or_else(|| refused("initial coalescence preflight plan is absent"))?;
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| refused("initial runtime original evidence is absent"))?;
        let inventory = InitialOriginalInventory::new(
            observed_maps(&self.original_maps, &self.original_read)?,
            &original.entry,
            executable.vma,
            plan,
        )?;
        let sizing = walk_windows(
            &inventory,
            &original.entry,
            self.profile,
            |index, vma, witness, geometry, entries| {
                let slot = &self.windows[index];
                let row = self
                    .rows
                    .get(vma)
                    .ok_or_else(|| refused("initial coalescence source row is absent"))?;
                if slot.vma != vma
                    || slot.original_witness != Some(witness)
                    || slot.geometry != Some(geometry)
                    || slot.entries != entries
                    || slot.id.is_some()
                    || slot.snapshot.is_some()
                    || row.original_index != witness.original_index
                    || row.original_span != witness.original_span
                    || row.start != witness.geometry.range.start()
                    || row.end != witness.geometry.range.end()
                    || row.offset != witness.offset
                    || row.file != witness.file
                {
                    return Err(refused(
                        "initial coalescence authenticated window differs from preflight",
                    ));
                }
                Ok(())
            },
        )?;
        if self.preflight_sizing != Some(sizing)
            || self.preflight_filled != sizing.windows
            || self.rows.len() != sizing.vmas
        {
            return Err(refused(
                "initial coalescence authenticated window sizing differs",
            ));
        }
        // Only the actual completed/bootstrap source proof reaches identity
        // minting; all preflight storage remains descriptive and ID-free.
        for _ in &self.rows {
            self.identities
                .push(crate::gate::domain::new_core_identity()?);
        }
        for index in 0..sizing.windows {
            let slot = &mut self.windows[index];
            slot.id = Some(SourceWindowId {
                identity: self.identities[slot.vma],
                index,
            });
            self.planned += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
