use super::*;

pub(super) struct Destination<'a> {
    pub(super) observation: &'a mut StackObservationStorage,
    pub(super) word: &'a mut WordObservation,
    pub(super) access: &'a mut PagemapAccess,
    pub(super) eof: &'a mut [u8; 2],
    pub(super) progress: &'a mut StackCaptureProgress,
}
pub(super) struct MetadataExpected<'a> {
    pub(super) profile: &'a ProfileDescription,
    pub(super) original_maps: &'a [u8],
    pub(super) geometry: &'a OperandGeometry,
    pub(super) maps: &'a [u8],
}

/// Scoped settled authority. Its constructor performs actual singleton/stop
/// authentication. It contains no original-release or native-completion right.
pub(in super::super) struct SettledStackRead<'a> {
    owner: &'a Owner,
    native: &'a NativeLifecycle,
    stop: &'a AdmissionStop,
    membership: &'a mut [u8],
    until: Instant,
}
impl<'a> SettledStackRead<'a> {
    pub(in super::super) fn acquire(
        owner: &'a Owner,
        native: &'a NativeLifecycle,
        stop: &'a AdmissionStop,
        membership: &'a mut [u8],
        until: Instant,
    ) -> Result<Self, LaunchError> {
        current(owner, native, stop, membership, until)?;
        Ok(Self {
            owner,
            native,
            stop,
            membership,
            until,
        })
    }
    fn recheck(&mut self) -> Result<(), LaunchError> {
        current(
            self.owner,
            self.native,
            self.stop,
            self.membership,
            self.until,
        )
    }
}
pub(in super::super) struct TraceStackRead<'a> {
    owner: &'a Owner,
    native: &'a NativeLifecycle,
    actual: NativeStackHeldView<'a>,
    membership: &'a mut [u8],
}
impl<'a> TraceStackRead<'a> {
    pub(in super::super) fn acquire(
        owner: &'a Owner,
        native: &'a NativeLifecycle,
        actual: NativeStackHeldView<'a>,
        membership: &'a mut [u8],
    ) -> Result<Self, LaunchError> {
        held(owner, native, &actual, membership, true)?;
        Ok(Self {
            owner,
            native,
            actual,
            membership,
        })
    }
    fn recheck(&mut self) -> Result<(), LaunchError> {
        held(self.owner, self.native, &self.actual, self.membership, true)
    }
}
pub(in super::super) struct FailedHeldStackRead<'a> {
    owner: &'a Owner,
    native: &'a NativeLifecycle,
    actual: NativeStackHeldView<'a>,
    membership: &'a mut [u8],
}
impl<'a> FailedHeldStackRead<'a> {
    pub(in super::super) fn acquire(
        owner: &'a Owner,
        native: &'a NativeLifecycle,
        actual: NativeStackHeldView<'a>,
        membership: &'a mut [u8],
    ) -> Result<Self, LaunchError> {
        held(owner, native, &actual, membership, false)?;
        Ok(Self {
            owner,
            native,
            actual,
            membership,
        })
    }
    fn recheck(&mut self) -> Result<(), LaunchError> {
        held(
            self.owner,
            self.native,
            &self.actual,
            self.membership,
            false,
        )
    }
}

/// Metadata and geometry are checked before pagemap, and pagemap before PEEK.
/// Later independent post-read state/maps are retained even if an earlier
/// request failed, provided the actual stop and original deadline still hold.
pub(super) fn capture(
    owner: &Owner,
    until: Instant,
    destination: Destination<'_>,
    expected: MetadataExpected<'_>,
    strict: bool,
    gate: &mut impl FnMut() -> Result<(), LaunchError>,
) -> Result<(), LaunchError> {
    let Destination {
        observation,
        word,
        access,
        eof,
        progress,
    } = destination;
    gate()?;
    let mut first = None;
    progress.stage = StackCaptureStage::Smaps;
    retain(
        progress,
        &mut first,
        io::capture_file(
            owner,
            until,
            c"smaps",
            &mut observation.smaps,
            &mut observation.smaps_capture,
            &mut eof[0],
        ),
    );
    if first.is_none() && strict {
        let metadata = (|| {
            let index = expected
                .profile
                .stack
                .require_current(expected.original_maps, expected.maps)?;
            let raw = observation.smaps_capture.bytes(&observation.smaps)?;
            if validate_smaps(raw, expected.maps, index)? != expected.profile.metadata {
                return Err(StackError::Metadata);
            }
            Ok(())
        })();
        let result = progress.validate(metadata);
        retain(progress, &mut first, result);
    }
    if first.is_none() {
        progress.stage = StackCaptureStage::Pagemap;
        retain(
            progress,
            &mut first,
            io::capture_pagemap(owner, until, expected.geometry, word, access),
        );
    }
    if first.is_none() {
        progress.stage = StackCaptureStage::Word;
        retain(
            progress,
            &mut first,
            io::capture_word(owner, until, expected.geometry, word, access),
        );
    }
    progress.stage = StackCaptureStage::Recheck;
    if let Err(error) = gate() {
        retain(progress, &mut first, Err(error));
        return Err(first.expect("retained held authority failure"));
    }
    progress.stage = StackCaptureStage::State;
    retain(
        progress,
        &mut first,
        observation.state.capture(owner, until),
    );
    if let Err(error) = bootstrap::physical(owner, until) {
        retain(progress, &mut first, Err(error));
        return Err(first.expect("retained held authority failure"));
    }
    progress.stage = StackCaptureStage::Maps;
    retain(
        progress,
        &mut first,
        io::capture_file(
            owner,
            until,
            c"maps",
            &mut observation.maps,
            &mut observation.maps_capture,
            &mut eof[1],
        ),
    );
    progress.stage = StackCaptureStage::Recheck;
    retain(progress, &mut first, gate());
    first.map_or(Ok(()), Err)
}

impl NativeStackWordCapture {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            observation: StackObservationStorage::empty(),
            word: WordObservation::default(),
            pagemap_access: PagemapAccess::default(),
            progress: StackCaptureProgress::empty(),
            eof: [0; 2],
            association: None,
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
            self.observation
                .payload_bytes()
                .map_err(|_| invalid("owned stack word allocation tally differs"))?,
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
        self.observation.set_fault(
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
            .validate(self.observation.allocate_payloads())?;
        self.progress.stage = StackCaptureStage::Allocated;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        if !self.progress.complete {
            self.observation.mark_aborted();
            self.progress.aborted();
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn attempted(&self) -> bool {
        self.progress.started
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn view(&self) -> StackWordView<'_> {
        StackWordView {
            observation: &self.observation,
            word: &self.word,
            pagemap_access: &self.pagemap_access,
            association: self.association.as_ref(),
            complete: self.progress.complete,
            first_failure: self.progress.first_failure,
        }
    }
    fn destination(&mut self) -> Destination<'_> {
        Destination {
            observation: &mut self.observation,
            word: &mut self.word,
            access: &mut self.pagemap_access,
            eof: &mut self.eof,
            progress: &mut self.progress,
        }
    }
    fn validate_expected(&mut self, expected: &StackWordExpected<'_>) -> Result<(), LaunchError> {
        self.progress.stage = StackCaptureStage::Validate;
        self.progress.validate(self.observation.require_ready())?;
        self.progress.validate(validate_state(
            &self.observation.state,
            expected.profile.layout,
        ))?;
        self.progress
            .validate(self.pagemap_access.validate_for(&self.word.pagemap))?;
        self.progress
            .validate(self.word.validate(expected.geometry))?;
        let maps = self
            .progress
            .validate(self.observation.maps_capture.bytes(&self.observation.maps))?;
        let smaps = self.progress.validate(
            self.observation
                .smaps_capture
                .bytes(&self.observation.smaps),
        )?;
        let index = self.progress.validate(
            expected
                .profile
                .stack
                .require_current(expected.original_maps, maps),
        )?;
        let metadata = self.progress.validate(validate_smaps(smaps, maps, index))?;
        if maps != expected.maps
            || self.observation.state.state != expected.state.state
            || self.word.bytes != *expected.word
            || metadata != expected.profile.metadata
        {
            return Err(invalid(
                "owned stack frozen phase state, word, or maps differ",
            ));
        }
        Ok(())
    }
    fn precheck(&mut self, expected: &StackWordExpected<'_>) -> Result<(), LaunchError> {
        self.progress.validate(self.observation.require_ready())?;
        self.progress
            .validate(validate_state(expected.state, expected.profile.layout))?;
        if expected.geometry.stack != expected.profile.stack.range()
            || expected.geometry.island != expected.profile.island
        {
            return Err(invalid("owned stack frozen phase profile differs"));
        }
        // Geometry is fully reconstructed by the unchanged word/pagemap reader
        // before use. No current/successor RSP is used to select a new slot.
        Ok(())
    }
    pub(in super::super) fn capture_settled(
        &mut self,
        mut read: SettledStackRead<'_>,
        phase: SettledWordPhase,
        expected: StackWordExpected<'_>,
    ) -> Result<(), LaunchError> {
        let result = (|| {
            self.progress.begin()?;
            self.precheck(&expected)?;
            require_profile_stop(expected.profile, read.stop)?;
            self.association = Some(match phase {
                SettledWordPhase::B => StackCaptureAssociation::B {
                    stop: read.stop.clone(),
                    until: read.until,
                },
                SettledWordPhase::D => StackCaptureAssociation::D {
                    stop: read.stop.clone(),
                    until: read.until,
                },
            });
            let owner = read.owner;
            let until = read.until;
            capture(
                owner,
                until,
                self.destination(),
                MetadataExpected {
                    profile: expected.profile,
                    original_maps: expected.original_maps,
                    geometry: expected.geometry,
                    maps: expected.maps,
                },
                true,
                &mut || read.recheck(),
            )?;
            self.validate_expected(&expected)?;
            owner.time_left(until, "owned stack settled word completion")?;
            self.progress.complete = true;
            self.progress.stage = StackCaptureStage::Complete;
            Ok(())
        })();
        if let Err(error) = &result {
            self.progress.fail(error);
        }
        result
    }
    pub(in super::super) fn capture_trace(
        &mut self,
        mut read: TraceStackRead<'_>,
        expected: StackWordExpected<'_>,
    ) -> Result<(), LaunchError> {
        let result = (|| {
            self.progress.begin()?;
            self.precheck(&expected)?;
            require_profile_stop(expected.profile, read.actual.original())?;
            if !std::ptr::eq(expected.state, read.actual.state())
                || expected.maps != read.actual.maps()
                || expected.state.state.registers.orig_rax != u64::MAX
            {
                return Err(invalid(
                    "owned stack trace expectation is not its actual raw state",
                ));
            }
            self.association = Some(StackCaptureAssociation::C {
                original: read.actual.original().clone(),
                raw_wait: read.actual.raw_wait(),
                ordinal: 3,
                until: read.actual.until(),
            });
            let owner = read.owner;
            let until = read.actual.until();
            capture(
                owner,
                until,
                self.destination(),
                MetadataExpected {
                    profile: expected.profile,
                    original_maps: expected.original_maps,
                    geometry: expected.geometry,
                    maps: expected.maps,
                },
                true,
                &mut || read.recheck(),
            )?;
            self.validate_expected(&expected)?;
            owner.time_left(until, "owned stack trace word completion")?;
            self.progress.complete = true;
            self.progress.stage = StackCaptureStage::Complete;
            Ok(())
        })();
        if let Err(error) = &result {
            self.progress.fail(error);
        }
        result
    }
    pub(in super::super) fn capture_failed_held(
        &mut self,
        mut read: FailedHeldStackRead<'_>,
        profile: &ProfileDescription,
        original_maps: &[u8],
        geometry: &OperandGeometry,
    ) -> Result<(), LaunchError> {
        let result = (|| {
            self.progress.begin()?;
            self.progress.validate(self.observation.require_ready())?;
            require_profile_stop(profile, read.actual.original())?;
            if geometry.stack != profile.stack.range() || geometry.island != profile.island {
                return Err(invalid("owned stack diagnostic frozen geometry differs"));
            }
            self.association = Some(StackCaptureAssociation::FailedHeld {
                original: read.actual.original().clone(),
                raw_wait: read.actual.raw_wait(),
                ordinal: 3,
                until: read.actual.until(),
            });
            let owner = read.owner;
            let until = read.actual.until();
            // No effect/eligibility/state equality is inferred. Actual changed
            // masks, PKRU, permissions and initialized prefixes remain visible.
            // Pagemap is still observed before any diagnostic PEEK.
            capture(
                owner,
                until,
                self.destination(),
                MetadataExpected {
                    profile,
                    original_maps,
                    geometry,
                    maps: &[],
                },
                false,
                &mut || read.recheck(),
            )?;
            owner.time_left(until, "owned stack failed-held diagnostic completion")?;
            self.progress.complete = true;
            self.progress.stage = StackCaptureStage::Complete;
            Ok(())
        })();
        if let Err(error) = &result {
            self.progress.fail(error);
        }
        result
    }
}
fn require_profile_stop(
    profile: &ProfileDescription,
    stop: &AdmissionStop,
) -> Result<(), LaunchError> {
    if stop.identity != profile.restored.identity
        || stop.token.session != profile.restored.token.session
        || stop.token.tid != profile.restored.token.tid
        || stop.token.task != profile.restored.token.task
        || stop.token.sequence < profile.restored.token.sequence
        || stop.signal.is_some()
        || !matches!(
            stop.phase,
            AdmissionPhase::EntryReady | AdmissionPhase::Restored
        )
    {
        return Err(invalid(
            "owned stack phase differs from actual original stack identity",
        ));
    }
    Ok(())
}

pub(super) fn temporary_bytes() -> Result<usize, LaunchError> {
    [
        size_of::<Destination<'_>>(),
        size_of::<MetadataExpected<'_>>(),
        size_of::<SettledStackRead<'_>>(),
        size_of::<TraceStackRead<'_>>(),
        size_of::<FailedHeldStackRead<'_>>(),
    ]
    .into_iter()
    .try_fold(0, add)
}
