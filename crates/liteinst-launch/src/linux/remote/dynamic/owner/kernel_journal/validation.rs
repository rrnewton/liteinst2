use super::*;

impl Attempt {
    fn record(&self, slot: KernelStateSlot) -> Result<u8, LaunchError> {
        self.raw_slots[slot.index()].ok_or(invalid("kernel journal raw phase is absent"))
    }
    fn info(&self, record: u8) -> Result<KernelSyscallInfo, LaunchError> {
        self.facts()
            .find_map(|fact| match fact {
                KernelJournalFact::SyscallInfo {
                    record: found,
                    info,
                } if *found == record => Some(*info),
                _ => None,
            })
            .ok_or(invalid("kernel journal syscall information is absent"))
    }
    fn raw_tid(&self, record: u8) -> Result<i32, LaunchError> {
        self.facts()
            .find_map(|fact| match fact {
                KernelJournalFact::RawStop {
                    record: found, tid, ..
                } if *found == record => Some(*tid),
                _ => None,
            })
            .ok_or(invalid("kernel journal raw identity is absent"))
    }
    fn raw_status(&self, record: u8) -> Result<i32, LaunchError> {
        self.facts()
            .find_map(|fact| match fact {
                KernelJournalFact::RawStop {
                    record: found,
                    status,
                    ..
                } if *found == record => Some(*status),
                _ => None,
            })
            .ok_or(invalid("kernel journal raw status is absent"))
    }
    fn same_state(&self, slot: KernelStateSlot, actual: &TaskStateSnapshot) -> bool {
        let state = &self.states[slot.index()];
        state.status == KernelCaptureStatus::Complete
            && state.registers == Some(actual.registers)
            && state.mask == actual.mask
            && state.length == actual.xstate.len()
            && state
                .bytes
                .as_ref()
                .is_some_and(|bytes| bytes[..state.length] == actual.xstate)
    }
    fn same_slots(&self, first: KernelStateSlot, second: KernelStateSlot) -> bool {
        let a = &self.states[first.index()];
        let b = &self.states[second.index()];
        a.status == KernelCaptureStatus::Complete
            && b.status == KernelCaptureStatus::Complete
            && a.registers == b.registers
            && a.mask == b.mask
            && a.length == b.length
            && a.bytes
                .as_ref()
                .zip(b.bytes.as_ref())
                .is_some_and(|(a, b)| {
                    a[..self.states[first.index()].length]
                        == b[..self.states[second.index()].length]
                })
    }
    fn validated(&self, slot: KernelStateSlot) -> bool {
        self.facts().any(|fact| {
            matches!(
                (slot, fact),
                (
                    KernelStateSlot::Entry,
                    KernelJournalFact::ValidatedEntry { .. }
                ) | (
                    KernelStateSlot::Creation | KernelStateSlot::Newborn,
                    KernelJournalFact::ValidatedCreation { .. }
                ) | (
                    KernelStateSlot::Exit,
                    KernelJournalFact::ValidatedExit { .. }
                )
            )
        })
    }
}

fn event_token(event: &DynamicEvent) -> Result<&DynamicStop, LaunchError> {
    let token = event
        .stop_token()
        .ok_or(invalid("kernel journal validated event lacks stop"))?;
    if token.tid != event.tid || token.task != event.task.map(|task| task.task) {
        return Err(invalid("kernel journal event and token identity differ"));
    }
    Ok(token)
}

impl KernelJournalWriter {
    pub(in crate::linux::remote::dynamic::owner) fn check_invocation(
        &self,
        handle: KernelAttemptHandle,
        stop: &AdmissionStop,
        input: &SelectedInput,
        before: &TaskStateSnapshot,
        until: Instant,
    ) -> Result<(), LaunchError> {
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        if self.active != Some(handle)
            || attempt.failure.is_some()
            || attempt.length != 0
            || attempt.binding.input != *input
            || attempt.binding.before != *before
            || attempt.binding.until != until
            || attempt.binding.original_stop.identity != stop.identity
            || attempt.binding.original_stop.token.session != stop.token.session
            || attempt.binding.original_stop.token.tid != stop.token.tid
            || attempt.binding.original_stop.token.task != stop.token.task
            || stop.token.sequence < attempt.binding.original_stop.token.sequence
        {
            return Err(invalid(
                "kernel journal original invocation does not match its reserved binding",
            ));
        }
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner) fn release_attempt(
        &mut self,
        handle: KernelAttemptHandle,
        phase: KernelReleasePhase,
        token: &DynamicStop,
    ) -> Result<(), LaunchError> {
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        let original = &attempt.binding.original_stop;
        if token.session != handle.id.session || token.tid != original.token.tid
            || token.task != Some(original.identity.task) || token.sequence < original.token.sequence
            || attempt.facts().any(|fact| matches!(fact, KernelJournalFact::ReleaseAttempt { phase: found, .. } if *found == phase))
            || match phase {
                KernelReleasePhase::Original => attempt.length != 0,
                KernelReleasePhase::Entry => !attempt.validated(KernelStateSlot::Entry),
                KernelReleasePhase::Creation => !attempt.validated(KernelStateSlot::Creation),
            }
        { return Err(invalid("kernel journal release has no exact preceding phase")); }
        attempt.stage = match phase {
            KernelReleasePhase::Original => KernelJournalStage::OriginalRelease,
            KernelReleasePhase::Entry => KernelJournalStage::EntryRelease,
            KernelReleasePhase::Creation => KernelJournalStage::CreationRelease,
        };
        attempt.append(KernelJournalFact::ReleaseAttempt {
            phase,
            stop: token.into(),
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn release_succeeded(
        &mut self,
        handle: KernelAttemptHandle,
        phase: KernelReleasePhase,
        token: &DynamicStop,
    ) -> Result<(), LaunchError> {
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        let stop = token.into();
        if attempt.facts().last() != Some(&KernelJournalFact::ReleaseAttempt { phase, stop }) {
            return Err(invalid(
                "kernel journal release success has no matching attempt",
            ));
        }
        attempt.append(KernelJournalFact::ReleaseSucceeded { phase, stop })
    }
    pub(in crate::linux::remote::dynamic::owner) fn validated_entry(
        &mut self,
        handle: KernelAttemptHandle,
        event: &DynamicEvent,
        actual: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        let token = event_token(event)?;
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        let record = attempt.record(KernelStateSlot::Entry)?;
        let info = attempt.info(record)?;
        let expected_arguments = arguments(attempt.binding.input.registers());
        let mut raw_arguments = [0; 6];
        for (i, value) in raw_arguments.iter_mut().enumerate() {
            *value = info.word(32 + i * 8);
        }
        if event.task != Some(attempt.binding.original_stop.identity)
            || token.session != handle.id.session
            || attempt.raw_tid(record)? != event.tid
            || attempt.validated(KernelStateSlot::Entry)
            || attempt.raw_status(record)? != (((libc::SIGTRAP | 0x80) << 8) | 0x7f)
            || !attempt.same_state(KernelStateSlot::Entry, actual)
            || info.operation() != 1
            || info.arch() != 0xc000_003e
            || info.ip() != actual.registers.rip
            || info.sp() != actual.registers.rsp
            || info.word(24) != attempt.binding.input.registers().rax
            || raw_arguments != expected_arguments
            || event.kind
                != (DynamicEventKind::SyscallEntry {
                    number: info.word(24),
                    arguments: expected_arguments,
                })
            || !attempt.facts().any(|fact| {
                matches!(
                    fact,
                    KernelJournalFact::ReleaseSucceeded {
                        phase: KernelReleasePhase::Original,
                        ..
                    }
                )
            })
        {
            return Err(invalid(
                "kernel journal ENTRY validation differs from raw evidence",
            ));
        }
        attempt.stage = KernelJournalStage::EntryValidation;
        attempt.append(KernelJournalFact::ValidatedEntry {
            record,
            stop: token.into(),
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn validated_creation(
        &mut self,
        handle: KernelAttemptHandle,
        parent: &DynamicEvent,
        newborn: &DynamicEvent,
    ) -> Result<(), LaunchError> {
        let parent_token = event_token(parent)?;
        let newborn_token = event_token(newborn)?;
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        let parent_record = attempt.record(KernelStateSlot::Creation)?;
        let newborn_record = attempt.record(KernelStateSlot::Newborn)?;
        let child = newborn
            .task
            .ok_or(invalid("kernel journal joined newborn lacks identity"))?;
        let original = attempt.binding.original_stop.identity;
        let child_number = attempt.facts().find_map(|fact| match fact {
            KernelJournalFact::EventMessage { record, value } if *record == parent_record => {
                Some(*value)
            }
            _ => None,
        });
        if attempt.validated(KernelStateSlot::Creation)
            || !attempt.validated(KernelStateSlot::Entry)
            || attempt.binding.input.registers().rax != libc::SYS_clone as u64
            || parent.task != Some(original)
            || parent.kind != (DynamicEventKind::Created { child })
            || newborn.kind != (DynamicEventKind::Newborn { parent: original })
            || child.process != original.process
            || child.address_space != original.address_space
            || child.generation != original.generation
            || child.task == original.task
            || parent_token.session != handle.id.session
            || newborn_token.session != handle.id.session
            || attempt.raw_tid(parent_record)? != parent.tid
            || attempt.raw_tid(newborn_record)? != newborn.tid
            || attempt.raw_status(parent_record)?
                != ((libc::PTRACE_EVENT_CLONE << 16) | (libc::SIGTRAP << 8) | 0x7f)
            || attempt.raw_status(newborn_record)?
                != ((libc::PTRACE_EVENT_STOP << 16) | (libc::SIGTRAP << 8) | 0x7f)
            || child_number != Some(newborn.tid as u64)
            || attempt.states[KernelStateSlot::Creation.index()].status
                != KernelCaptureStatus::Complete
            || attempt.states[KernelStateSlot::Newborn.index()].status
                != KernelCaptureStatus::Complete
        {
            return Err(invalid(
                "kernel journal creation join differs from captured identities",
            ));
        }
        attempt.stage = KernelJournalStage::CreationValidation;
        attempt.append(KernelJournalFact::ValidatedCreation {
            parent_record,
            newborn_record,
            parent: parent_token.into(),
            newborn: newborn_token.into(),
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn validated_exit(
        &mut self,
        handle: KernelAttemptHandle,
        event: &DynamicEvent,
        actual: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        let token = event_token(event)?;
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        let record = attempt.record(KernelStateSlot::Exit)?;
        let info = attempt.info(record)?;
        if event.task != Some(attempt.binding.original_stop.identity)
            || token.session != handle.id.session
            || attempt.raw_tid(record)? != event.tid
            || attempt.validated(KernelStateSlot::Exit)
            || attempt.raw_status(record)? != (((libc::SIGTRAP | 0x80) << 8) | 0x7f)
            || !attempt.validated(KernelStateSlot::Entry)
            || !attempt.same_state(KernelStateSlot::Exit, actual)
            || info.operation() != 2
            || info.arch() != 0xc000_003e
            || info.ip() != actual.registers.rip
            || info.sp() != actual.registers.rsp
            || event.kind
                != (DynamicEventKind::SyscallExit {
                    result: info.word(24) as i64,
                    is_error: info.initialized[32] != 0,
                })
            || info.word(24) != actual.registers.rax
        {
            return Err(invalid(
                "kernel journal EXIT validation differs from raw evidence",
            ));
        }
        attempt.stage = KernelJournalStage::ExitValidation;
        attempt.append(KernelJournalFact::ValidatedExit {
            record,
            stop: token.into(),
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn bridge_begin(
        &mut self,
        handle: KernelAttemptHandle,
        task: DynamicTask,
        newborn: bool,
    ) -> Result<(), LaunchError> {
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        let slot = if newborn {
            KernelStateSlot::Newborn
        } else {
            KernelStateSlot::Exit
        };
        let source_record = attempt.record(slot)?;
        let identity_matches = if newborn {
            attempt.facts().any(|fact| matches!(fact, KernelJournalFact::ValidatedCreation { newborn, .. } if newborn.task == Some(task.task)))
        } else {
            task == attempt.binding.original_stop.identity
        };
        if !identity_matches || !attempt.validated(slot) || !attempt.validated(KernelStateSlot::Exit)
            || attempt.facts().any(|fact| matches!(fact, KernelJournalFact::BridgeBegin { source_record: source, .. } if *source == source_record))
        { return Err(invalid("kernel journal bridge has no validated original state")); }
        attempt.stage = if newborn {
            KernelJournalStage::NewbornBridge
        } else {
            KernelJournalStage::ParentBridge
        };
        attempt.append(KernelJournalFact::BridgeBegin {
            source_record,
            task,
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn bridge_committed(
        &mut self,
        handle: KernelAttemptHandle,
        slot: KernelStateSlot,
        stop: &AdmissionStop,
    ) -> Result<(), LaunchError> {
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        let source = if slot == KernelStateSlot::ParentBridge {
            KernelStateSlot::Exit
        } else {
            KernelStateSlot::Newborn
        };
        let record = attempt.record(source)?;
        if !attempt.same_slots(source, slot) || stop.token.session != handle.id.session
            || stop.token.task != Some(stop.identity.task) || attempt.raw_tid(record)? != stop.token.tid
            || !attempt.facts().any(|fact| matches!(fact, KernelJournalFact::BridgeBegin { source_record, task } if *source_record == record && *task == stop.identity))
            || attempt.facts().any(|fact| matches!(fact, KernelJournalFact::BridgeComplete { slot: found, .. } if *found == slot))
        { return Err(invalid("kernel journal bridge completion differs from original raw state")); }
        attempt.append(KernelJournalFact::BridgeComplete {
            slot,
            stop: (&stop.token).into(),
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn transport_complete(
        &mut self,
        handle: KernelAttemptHandle,
        parent: &AdmissionStop,
        newborn: Option<&AdmissionStop>,
    ) -> Result<(), LaunchError> {
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        let parent = (&parent.token).into();
        let newborn = newborn.map(|stop| (&stop.token).into());
        if attempt
            .facts()
            .any(|fact| matches!(fact, KernelJournalFact::TransportComplete { .. }))
            || !attempt.facts().any(|fact| {
                *fact
                    == (KernelJournalFact::BridgeComplete {
                        slot: KernelStateSlot::ParentBridge,
                        stop: parent,
                    })
            })
            || newborn.is_some() != attempt.validated(KernelStateSlot::Newborn)
            || newborn.is_some_and(|stop| {
                !attempt.facts().any(|fact| {
                    *fact
                        == (KernelJournalFact::BridgeComplete {
                            slot: KernelStateSlot::NewbornBridge,
                            stop,
                        })
                })
            })
        {
            return Err(invalid(
                "kernel journal transport lacks exact completed bridges",
            ));
        }
        attempt.stage = KernelJournalStage::Transport;
        attempt.append(KernelJournalFact::TransportComplete { parent, newborn })
    }
}
