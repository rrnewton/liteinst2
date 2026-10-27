use super::*;

impl PreparedStackProfileCapture {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            diagnostic: PreparedStackProfile::empty(),
            progress: StackCaptureProgress::empty(),
            eof: [0; 2],
            association: None,
            provenance: false,
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn reservation_bytes()
    -> Result<usize, LaunchError> {
        add(size_of::<Self>(), 3 * BYTES)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocated_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        add(
            size_of::<Self>(),
            self.diagnostic
                .observation
                .payload_bytes()
                .map_err(|_| invalid("owned stack profile allocation tally differs"))?,
        )
    }
    /// Test-only configuration of the actual installed three-payload allocator.
    /// It cannot create a capture, replace storage, or change native eligibility.
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn set_allocation_fault(
        &mut self,
        fail_before: Option<usize>,
        panic_after: Option<usize>,
    ) {
        assert_eq!(self.progress.stage, StackCaptureStage::Empty);
        assert!(!self.progress.started && !self.progress.complete);
        assert!(self.progress.first_failure.is_none());
        assert!(fail_before.is_none_or(|index| index < 3));
        assert!(panic_after.is_none_or(|index| index < 3));
        self.diagnostic.observation.set_fault(
            super::super::super::runtime_stack::storage::AllocationFault {
                fail_before,
                panic_after,
            },
        );
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocate_payloads(
        &mut self,
    ) -> Result<(), LaunchError> {
        let result = self.diagnostic.allocate_payloads();
        self.progress.validate(result)?;
        self.progress.stage = StackCaptureStage::Allocated;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        if !self.progress.complete {
            self.diagnostic.mark_aborted();
            self.progress.aborted();
        }
    }
    // Read-only progress projection for native retention controls.
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn progress(
        &self,
    ) -> &StackCaptureProgress {
        &self.progress
    }
    // Read-only startup storage projection for native retention/allocation controls.
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn observation(
        &self,
    ) -> &StackObservationStorage {
        &self.diagnostic.observation
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn acquire(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        boot: &BootstrapMm,
        sources: &PreparedInitialSources,
        until: Instant,
    ) -> Result<(), LaunchError> {
        let result = self.acquire_inner(owner, native, boot, sources, until);
        if let Err(error) = &result {
            self.progress.fail(error);
        }
        result
    }
    fn acquire_inner(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        boot: &BootstrapMm,
        sources: &PreparedInitialSources,
        until: Instant,
    ) -> Result<(), LaunchError> {
        self.progress.begin()?;
        self.progress
            .validate(self.diagnostic.observation.require_ready())?;
        sources.require_stack_start(owner, native, boot, until)?;
        let (original, read) = sources.original_maps();
        if !read.complete
            || read.failure.is_some()
            || read.copied_bytes == 0
            || read.copied_bytes > BYTES
        {
            return Err(invalid("owned stack original map capture is incomplete"));
        }
        let original = original
            .get(..read.copied_bytes)
            .ok_or_else(|| invalid("owned stack original map prefix differs"))?;
        let baseline = sources.runtime_baseline_maps().map_err(gate_error)?;
        self.association = Some(ProfileCaptureStamp {
            stop: boot.stop.clone(),
            original_pointer: original.as_ptr() as usize,
            original_length: original.len(),
            until,
        });
        self.progress.stage = StackCaptureStage::Layout;
        io::capture_layout(owner, until, &mut self.diagnostic.layout_evidence)?;
        let observation = &mut self.diagnostic.observation;
        let mut first = None;
        self.progress.stage = StackCaptureStage::Smaps;
        retain(
            &mut self.progress,
            &mut first,
            io::capture_file(
                owner,
                until,
                c"smaps",
                &mut observation.smaps,
                &mut observation.smaps_capture,
                &mut self.eof[0],
            ),
        );
        // Metadata failure does not discard independent later state/map
        // diagnostics while actual custody and the original deadline survive.
        if let Err(error) = bootstrap::physical(owner, until) {
            retain(&mut self.progress, &mut first, Err(error));
            return Err(first.expect("recorded custody failure"));
        }
        self.progress.stage = StackCaptureStage::State;
        retain(
            &mut self.progress,
            &mut first,
            observation.state.capture(owner, until),
        );
        if let Err(error) = bootstrap::physical(owner, until) {
            retain(&mut self.progress, &mut first, Err(error));
            return Err(first.expect("recorded custody failure"));
        }
        self.progress.stage = StackCaptureStage::Maps;
        retain(
            &mut self.progress,
            &mut first,
            io::capture_file(
                owner,
                until,
                c"maps",
                &mut observation.maps,
                &mut observation.maps_capture,
                &mut self.eof[1],
            ),
        );
        self.progress.stage = StackCaptureStage::Recheck;
        retain(
            &mut self.progress,
            &mut first,
            sources.require_stack_start(owner, native, boot, until),
        );
        if let Some(error) = first {
            return Err(error);
        }
        self.progress.stage = StackCaptureStage::Validate;
        self.progress
            .validate(self.diagnostic.validate(ProfileInput {
                bootstrap: boot,
                original_maps: original,
                baseline_maps: baseline,
            }))?;
        owner.time_left(until, "owned stack initial capture completion")?;
        self.provenance = true;
        self.progress.complete = true;
        self.progress.stage = StackCaptureStage::Complete;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn identity(
        &self,
    ) -> Result<OriginalStackIdentity<'_>, LaunchError> {
        if !self.provenance
            || !self.progress.complete
            || self.progress.first_failure.is_some()
            || self.association.is_none()
            || self.diagnostic.description().is_none()
        {
            return Err(invalid(
                "owned stack profile lacks actual completed acquisition",
            ));
        }
        Ok(OriginalStackIdentity { captured: self })
    }
}
impl OriginalStackIdentity<'_> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn description(
        &self,
    ) -> &ProfileDescription {
        self.captured
            .diagnostic
            .description()
            .expect("actual original stack identity")
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn observation(
        &self,
    ) -> &StackObservationStorage {
        &self.captured.diagnostic.observation
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn layout_evidence(
        &self,
    ) -> &PkuLayoutEvidence {
        &self.captured.diagnostic.layout_evidence
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn stop(&self) -> &AdmissionStop {
        &self
            .captured
            .association
            .as_ref()
            .expect("actual original stack identity")
            .stop
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn until(&self) -> Instant {
        self.captured
            .association
            .as_ref()
            .expect("actual original stack identity")
            .until
    }
    pub(super) fn identity_key(&self, raw: &[u8]) -> Result<ProfileIdentityKey, LaunchError> {
        self.require_original(raw)?;
        let observation = self.observation();
        let description = self.description();
        Ok(ProfileIdentityKey {
            payloads: [
                BufferIdentity::of(&observation.smaps),
                BufferIdentity::of(&observation.maps),
                BufferIdentity::of(&observation.state.state.xstate),
            ],
            original: (raw.as_ptr() as usize, raw.len()),
            stop: self.stop().clone(),
            until: self.until(),
            stack: description.stack,
            metadata: description.metadata,
            layout: description.layout,
            raw_layout: *self.layout_evidence(),
            initial_rsp: description.initial_rsp,
            island: description.island.clone(),
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_original(
        &self,
        raw: &[u8],
    ) -> Result<(), LaunchError> {
        let stamp = self
            .captured
            .association
            .as_ref()
            .expect("actual original stack identity");
        if stamp.original_pointer != raw.as_ptr() as usize
            || stamp.original_length != raw.len()
            || self.description().restored != stamp.stop
        {
            return Err(invalid("owned stack original catalog buffer differs"));
        }
        self.description()
            .stack
            .require_current(
                raw,
                self.observation()
                    .maps_capture
                    .bytes(&self.observation().maps)
                    .map_err(|_| invalid("owned stack retained initial maps differ"))?,
            )
            .map_err(|_| invalid("owned stack retained original descriptor differs"))?;
        Ok(())
    }
}
