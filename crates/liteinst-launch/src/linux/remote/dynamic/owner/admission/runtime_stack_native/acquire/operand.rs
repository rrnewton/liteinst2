use super::*;

impl PreparedStackOperandCapture {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            diagnostic: PreparedStackOperand::empty(),
            progress: StackCaptureProgress::empty(),
            pagemap_access: PagemapAccess::default(),
            eof: [0; 2],
            association: None,
            provenance: None,
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
                .map_err(|_| invalid("owned stack operand allocation tally differs"))?,
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
        self.progress
            .validate(self.diagnostic.allocate_payloads())?;
        self.progress.stage = StackCaptureStage::Allocated;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        if !self.progress.complete {
            self.diagnostic.mark_aborted();
            self.progress.aborted();
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn progress(
        &self,
    ) -> &StackCaptureProgress {
        &self.progress
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn view(&self) -> StackWordView<'_> {
        StackWordView {
            observation: &self.diagnostic.observation,
            word: &self.diagnostic.word,
            pagemap_access: &self.pagemap_access,
            association: self.association.as_ref(),
            complete: self.progress.complete,
            first_failure: self.progress.first_failure,
        }
    }
    pub(in super::super) fn acquire(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        initial: &OriginalStackIdentity<'_>,
        context: &StackBeforeContext<'_, '_>,
        actual: NativeStackBeforeView<'_>,
        membership: &mut [u8],
    ) -> Result<(), LaunchError> {
        let result = self.acquire_inner(owner, native, initial, context, actual, membership);
        if let Err(error) = &result {
            self.progress.fail(error);
        }
        result
    }
    fn acquire_inner(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        initial: &OriginalStackIdentity<'_>,
        context: &StackBeforeContext<'_, '_>,
        actual: NativeStackBeforeView<'_>,
        membership: &mut [u8],
    ) -> Result<(), LaunchError> {
        let until = actual.until();
        self.progress.begin()?;
        self.progress
            .validate(self.diagnostic.observation.require_ready())?;
        current(owner, native, context.stop(), membership, until)?;
        initial.require_original(context.original_maps())?;
        if actual.stop() != context.stop()
            || context.until() != until
            || actual.baseline_maps() != context.baseline_maps()
            || !actual.state().complete
            || !actual.work().complete
            || actual.state().state != actual.work().state
            || actual.state().state.registers != context.before().registers
            || actual.state().state.xstate != context.before().xstate
            || actual.state().state.mask != context.before().signal_mask
            || context.before().token != context.stop().token
            || context.before().task != context.stop().identity
            || context.candidate().registers() != &actual.state().state.registers
            || context.candidate().range().start() != actual.state().state.registers.rip
            || context.island().range != initial.description().island
        {
            return Err(invalid(
                "owned stack operand differs from actual native before capture",
            ));
        }
        self.association = Some(StackCaptureAssociation::A {
            stop: actual.stop().clone(),
            source_id: context.source_id(),
            until,
        });
        self.progress.stage = StackCaptureStage::Layout;
        io::capture_layout(owner, until, &mut self.diagnostic.layout_evidence)?;
        let layout = self
            .progress
            .validate(self.diagnostic.layout_evidence.validate())?;
        if layout != initial.description().layout {
            return Err(invalid(
                "owned stack current component layout differs from startup",
            ));
        }
        // These are actual producer BEFORE/WORK slots, authenticated before A.
        // PEEK cannot manufacture eligibility by bypassing PKRU or AC.
        self.progress
            .validate(validate_state(actual.state(), layout))?;
        self.progress
            .validate(validate_state(actual.work(), layout))?;
        let geometry = self.progress.validate(OperandGeometry::derive(
            context.candidate().range().start(),
            context.candidate().bytes(),
            actual.state().state.registers.rsp,
            &initial.description().stack.range(),
            &initial.description().island,
        ))?;
        let mut gate = || current(owner, native, context.stop(), membership, until);
        word::capture(
            owner,
            until,
            word::Destination {
                observation: &mut self.diagnostic.observation,
                word: &mut self.diagnostic.word,
                access: &mut self.pagemap_access,
                eof: &mut self.eof,
                progress: &mut self.progress,
            },
            word::MetadataExpected {
                profile: initial.description(),
                original_maps: context.original_maps(),
                geometry: &geometry,
                maps: context.baseline_maps(),
            },
            true,
            &mut gate,
        )?;
        self.progress.stage = StackCaptureStage::Validate;
        self.progress.validate(
            self.pagemap_access
                .validate_for(&self.diagnostic.word.pagemap),
        )?;
        self.progress
            .validate(self.diagnostic.validate(OperandInput {
                profile: initial.description(),
                original_maps: context.original_maps(),
                expected_maps: context.baseline_maps(),
                current: &actual.state().state,
                current_stop: context.stop(),
                until,
                pc: context.candidate().range().start(),
                encoding: context.candidate().bytes(),
                island: &context.island().range,
            }))?;
        owner.time_left(until, "owned stack operand completion")?;
        self.provenance = Some(OperandCaptureStamp {
            origin: context.origin(),
            execution: context.execution(),
            profile: initial.identity_key(context.original_maps())?,
        });
        self.progress.stage = StackCaptureStage::Complete;
        self.progress.complete = true;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn operand(
        &self,
    ) -> Result<OwnedStackOperand<'_>, LaunchError> {
        if self.provenance.is_none()
            || !self.progress.complete
            || self.progress.first_failure.is_some()
            || !matches!(self.association, Some(StackCaptureAssociation::A { .. }))
            || self.diagnostic.description().is_none()
        {
            return Err(invalid(
                "owned stack operand lacks actual completed acquisition",
            ));
        }
        Ok(OwnedStackOperand { captured: self })
    }
}
impl OwnedStackOperand<'_> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_profile(
        &self,
        initial: &OriginalStackIdentity<'_>,
        original_maps: &[u8],
    ) -> Result<(), LaunchError> {
        let actual = initial.identity_key(original_maps)?;
        let retained = &self
            .captured
            .provenance
            .as_ref()
            .expect("actual owned stack operand")
            .profile;
        if &actual != retained {
            return Err(invalid(
                "owned stack operand belongs to a different actual startup capture",
            ));
        }
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn description(
        &self,
    ) -> &OperandDescription {
        self.captured
            .diagnostic
            .description()
            .expect("actual owned stack operand")
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn observation(
        &self,
    ) -> &StackObservationStorage {
        &self.captured.diagnostic.observation
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn word(&self) -> &WordObservation {
        &self.captured.diagnostic.word
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn layout_evidence(
        &self,
    ) -> &PkuLayoutEvidence {
        &self.captured.diagnostic.layout_evidence
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn pagemap_access(
        &self,
    ) -> &PagemapAccess {
        &self.captured.pagemap_access
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn before(&self) -> &TaskStateSnapshot {
        &self.observation().state.state
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn stop(&self) -> &AdmissionStop {
        &self.description().stop
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn until(&self) -> Instant {
        self.description().until
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn source_id(&self) -> SourceWindowId {
        match self
            .captured
            .association
            .as_ref()
            .expect("actual owned stack operand")
        {
            StackCaptureAssociation::A { source_id, .. } => *source_id,
            _ => unreachable!("actual A association"),
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn origin(&self) -> OriginId {
        self.captured
            .provenance
            .as_ref()
            .expect("actual owned stack operand")
            .origin
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn execution(&self) -> ExecutionId {
        self.captured
            .provenance
            .as_ref()
            .expect("actual owned stack operand")
            .execution
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn view(&self) -> StackWordView<'_> {
        self.captured.view()
    }
}
