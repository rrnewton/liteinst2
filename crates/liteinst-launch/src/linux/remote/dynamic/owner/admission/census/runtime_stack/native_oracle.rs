//! Read-only test assertions and typed copies of actual retained census data.
//! These values are diagnostic snapshots, never native completion constructors.
use super::super::super::runtime::stack::RuntimeStackIdentity;
use super::*;

pub(in crate::linux::remote::dynamic::owner::admission) struct StackChainInput<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) start: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) reservation: Reservation,
    pub(in crate::linux::remote::dynamic::owner::admission) identity: &'a RuntimeStackIdentity,
    pub(in crate::linux::remote::dynamic::owner::admission) logical_before: &'a ObservedStop,
    pub(in crate::linux::remote::dynamic::owner::admission) checkpoints: [NativeCheckpoint<'a>; 7],
    pub(in crate::linux::remote::dynamic::owner::admission) trace: NativeTrace,
    pub(in crate::linux::remote::dynamic::owner::admission) words: StackWordViews<'a>,
    pub(in crate::linux::remote::dynamic::owner::admission) call_id: Option<PotentialCallId>,
    pub(in crate::linux::remote::dynamic::owner::admission) sources: &'a PreparedInitialSources,
    pub(in crate::linux::remote::dynamic::owner::admission) current: OriginId,
    pub(in crate::linux::remote::dynamic::owner::admission) native_current: &'a AdmissionStop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AllocationSnapshot {
    address: usize,
    length: usize,
    capacity: usize,
}
fn allocation(bytes: &Vec<u8>) -> AllocationSnapshot {
    AllocationSnapshot {
        address: bytes.as_ptr() as usize,
        length: bytes.len(),
        capacity: bytes.capacity(),
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct StackCensusSnapshot {
    identity: u64,
    session: u64,
    space: AddressSpaceId,
    limits: Limits,
    state: State,
    origins_address: usize,
    origins_capacity: usize,
    history_address: usize,
    history_capacity: usize,
    origin_payloads: Vec<[AllocationSnapshot; 2]>,
    stack_payloads: Vec<(usize, Vec<AllocationSnapshot>, Option<(usize, usize)>)>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct StackPreparationSnapshot {
    binding: Option<Binding>,
    before: Option<ObservedStop>,
    before_allocation: Option<AllocationSnapshot>,
    buffers: [Vec<u8>; STATES],
    buffer_allocations: [AllocationSnapshot; STATES],
    evidence: Option<Box<[StackEvidence]>>,
    evidence_allocation: Option<(usize, usize)>,
    allocation: PayloadProgress,
    settled_bytes: usize,
    prepared: bool,
    committed: bool,
    header_bytes: usize,
    allocated_bytes: usize,
    fault: (Option<usize>, Option<usize>),
}
impl PreparedStackCensus {
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_evidence_bytes() -> usize {
        size_of::<StackEvidence>()
    }
    /// Configures only the existing callbacks, before any installed payload.
    /// After-install panic payload is exactly 0x5354434e_u32 (STCN).
    pub(in crate::linux::remote::dynamic::owner::admission) fn set_allocation_fault(
        &mut self,
        fail_before: Option<usize>,
        panic_after: Option<usize>,
    ) {
        assert!(!self.allocation.started && self.allocation.failure.is_none());
        assert!(self.binding.is_none() && self.before.is_none() && self.evidence.is_none());
        assert!(
            self.buffers
                .iter()
                .all(|v| v.is_empty() && v.capacity() == 0)
        );
        assert_eq!(self.settled_bytes, 0);
        assert!(!self.prepared && !self.committed);
        assert!(fail_before.is_none_or(|index| index < 17));
        assert!(panic_after.is_none_or(|index| index < 17));
        self.allocation_fail_before = fail_before;
        self.allocation_panic_after = panic_after;
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_snapshot(
        &self,
    ) -> StackPreparationSnapshot {
        StackPreparationSnapshot {
            binding: self.binding.clone(),
            before: self.before.clone(),
            before_allocation: self.before.as_ref().map(|v| allocation(&v.xstate)),
            buffers: self.buffers.clone(),
            buffer_allocations: std::array::from_fn(|i| allocation(&self.buffers[i])),
            evidence: self.evidence.clone(),
            evidence_allocation: self
                .evidence
                .as_ref()
                .map(|v| (v.as_ptr() as usize, v.len())),
            allocation: self.allocation,
            settled_bytes: self.settled_bytes,
            prepared: self.prepared,
            committed: self.committed,
            header_bytes: size_of::<Self>(),
            allocated_bytes: self.allocated_bytes().unwrap(),
            fault: (self.allocation_fail_before, self.allocation_panic_after),
        }
    }
}

fn observed(
    actual: &ObservedStop,
    checkpoint: NativeCheckpoint<'_>,
    original: &ObservedStop,
    phase: StopPhase,
    signal: Option<DynamicSignalInfo>,
) {
    assert_eq!(actual.token, checkpoint.stop.token);
    assert_eq!(actual.task, checkpoint.stop.identity);
    assert_eq!(actual.token.session, original.token.session);
    assert_eq!(actual.token.tid, original.token.tid);
    assert_eq!(actual.token.task, original.token.task);
    assert_eq!(actual.token.task, Some(original.task.task));
    assert_eq!(actual.task, original.task);
    assert_eq!(actual.task.generation, 0);
    assert_eq!(actual.logical_pc, checkpoint.state.registers.rip);
    assert_eq!(actual.registers, checkpoint.state.registers);
    assert_eq!(actual.xstate, checkpoint.state.xstate);
    assert_eq!(actual.signal_mask, checkpoint.state.mask);
    assert_eq!(actual.phase, phase);
    assert_eq!(actual.signal, signal);
    assert_eq!(actual.xstate.capacity(), MAX_XSTATE_BYTES);
    assert!((576..MAX_XSTATE_BYTES).contains(&actual.xstate.len()));
}
fn full_before(checkpoint: NativeCheckpoint<'_>, original: &ObservedStop) {
    assert_eq!(checkpoint.state.registers, original.registers);
    assert_eq!(checkpoint.state.xstate, original.xstate);
    assert_eq!(checkpoint.state.mask, original.signal_mask);
}
fn checkpoint_identity(
    checkpoint: NativeCheckpoint<'_>,
    original: &ObservedStop,
    phase: AdmissionPhase,
    previous_sequence: u64,
) {
    assert_eq!(checkpoint.stop.identity, original.task);
    assert_eq!(checkpoint.stop.token.session, original.token.session);
    assert_eq!(checkpoint.stop.token.tid, original.token.tid);
    assert_eq!(checkpoint.stop.token.task, original.token.task);
    assert!(checkpoint.stop.token.sequence > previous_sequence);
    assert_eq!(checkpoint.stop.phase, phase);
    assert!(checkpoint.stop.signal.is_none());
}
fn words(input: &StackChainInput<'_>, binding: &Binding) {
    let words = &input.words;
    let [a, b, c, d] = words.captures;
    assert_eq!(words.operand, &binding.operand);
    assert_eq!(ProfileRecord::from(words.profile), binding.profile);
    let (original, progress) = input.sources.original_maps();
    assert!(progress.started && progress.attempted && progress.complete);
    assert!(progress.failure.is_none());
    assert_eq!(words.original_maps, &original[..progress.copied_bytes]);
    assert_eq!(
        words.baseline_maps,
        input.sources.runtime_baseline_maps().unwrap()
    );
    assert_eq!(
        a.association,
        Some(&StackCaptureAssociation::A {
            stop: input.identity.stop().clone(),
            source_id: input.identity.source_id(),
            until: input.identity.until(),
        })
    );
    assert_eq!(
        b.association,
        Some(&StackCaptureAssociation::B {
            stop: input.checkpoints[2].stop.clone(),
            until: input.identity.until(),
        })
    );
    assert_eq!(
        c.association,
        Some(&StackCaptureAssociation::C {
            original: input.checkpoints[2].stop.clone(),
            raw_wait: (input.trace.tid, input.trace.status),
            ordinal: 3,
            until: input.identity.until(),
        })
    );
    assert_eq!(
        d.association,
        Some(&StackCaptureAssociation::D {
            stop: input.checkpoints[6].stop.clone(),
            until: input.identity.until(),
        })
    );
    for (index, view) in words.captures.iter().enumerate() {
        assert!(view.complete && view.first_failure.is_none());
        view.observation.require_ready().unwrap();
        let state = &view.observation.state;
        assert!(state.complete);
        for request in [
            state.registers_request,
            state.xstate_request,
            state.mask_request,
        ] {
            let request = request.expect("actual completed independent state request");
            assert_eq!(request.result, 0);
            assert_eq!(request.errno, None);
        }
        assert_eq!(
            state.requested_pointer,
            state.state.xstate.as_ptr() as usize
        );
        assert_eq!(state.returned_pointer, state.requested_pointer);
        assert_eq!(state.returned_length, state.state.xstate.len());
        assert_eq!(
            view.observation.state.state.xstate.capacity(),
            MAX_XSTATE_BYTES
        );
        assert_eq!(view.observation.maps.capacity(), MAX_XSTATE_BYTES);
        assert_eq!(view.observation.smaps.capacity(), MAX_XSTATE_BYTES);
        let maps = view
            .observation
            .maps_capture
            .bytes(&view.observation.maps)
            .unwrap();
        assert_eq!(
            maps,
            if index == 0 || index == 3 {
                words.baseline_maps
            } else {
                words.opened_maps
            }
        );
        view.pagemap_access
            .validate_for(&view.word.pagemap)
            .unwrap();
        let value = view.word.validate(&words.operand.geometry).unwrap();
        if index < 2 {
            assert_eq!(value, words.operand.value);
            assert_eq!(
                view.observation.state.state.registers,
                input.logical_before.registers
            );
            assert_eq!(
                view.observation.state.state.xstate,
                input.logical_before.xstate
            );
            assert_eq!(
                view.observation.state.state.mask,
                input.logical_before.signal_mask
            );
        } else {
            assert_eq!(&view.observation.state.state, input.checkpoints[3].state);
        }
    }
    assert_eq!(a.word.bytes, b.word.bytes);
    assert_eq!(c.word.bytes, d.word.bytes);
    let geometry = &words.operand.geometry;
    let offset = usize::try_from(geometry.slot.start - geometry.envelope.start).unwrap();
    let mut expected = a.word.bytes;
    let mut registers = input.logical_before.registers;
    registers.orig_rax = u64::MAX;
    registers.rip = words.operand.target;
    match geometry.operation {
        StackOperation::DirectCall => {
            assert!(input.call_id.is_some());
            assert_eq!(geometry.slot.start, registers.rsp.checked_sub(8).unwrap());
            registers.rsp = geometry.slot.start;
            expected[offset..offset + 8].copy_from_slice(&geometry.next_pc.to_le_bytes());
        }
        StackOperation::Return => {
            assert!(input.call_id.is_none());
            assert_eq!(geometry.slot.start, registers.rsp);
            registers.rsp = registers.rsp.checked_add(8).unwrap();
            assert_eq!(
                words.operand.target,
                u64::from_le_bytes(expected[offset..offset + 8].try_into().unwrap())
            );
        }
    }
    assert_eq!(c.word.bytes, expected);
    assert_eq!(input.checkpoints[3].state.registers, registers);
    assert_eq!(
        input.checkpoints[3].state.xstate,
        input.logical_before.xstate
    );
    assert_eq!(
        input.checkpoints[3].state.mask,
        input.logical_before.signal_mask
    );
}

impl ResumeCensus {
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_stack_chain(
        &self,
        input: StackChainInput<'_>,
    ) -> StackCensusSnapshot {
        let original = input.logical_before;
        let identity = input.identity;
        assert_eq!(self.state.generation, 0);
        assert_eq!(identity.stop().token, original.token);
        assert_eq!(identity.stop().identity, original.task);
        assert_eq!(identity.stop(), &input.words.operand.stop);
        assert_eq!(identity.operand_description(), input.words.operand);
        assert_eq!(original.phase, StopPhase::UserCheckpoint);
        assert!(original.signal.is_none());
        assert_eq!(self.state.history.len(), input.start + 7);
        let history = &self.state.history[input.start..];
        let phase = StopPhase::OwnedStackComplete {
            execution: identity.execution(),
        };
        let signal = DynamicSignalInfo {
            raw: input.trace.signal,
        };
        let mut previous = original;
        for (index, record) in history[..3].iter().enumerate() {
            let HistoryRecord::Refreshed {
                origin,
                before,
                after,
            } = record
            else {
                panic!("stack opening missing")
            };
            assert_eq!(*origin, identity.origin());
            assert_eq!(before, previous);
            assert_eq!(before.xstate.capacity(), MAX_XSTATE_BYTES);
            checkpoint_identity(
                input.checkpoints[index],
                original,
                AdmissionPhase::Restored,
                before.token.sequence,
            );
            full_before(input.checkpoints[index], original);
            observed(
                after,
                input.checkpoints[index],
                original,
                StopPhase::UserCheckpoint,
                None,
            );
            previous = after;
        }
        let HistoryRecord::Consumed { origin, evidence } = &history[3] else {
            panic!("stack consumption missing")
        };
        assert_eq!(*origin, identity.origin());
        assert_eq!(&evidence.before, previous);
        assert_eq!(evidence.before.xstate.capacity(), MAX_XSTATE_BYTES);
        checkpoint_identity(
            input.checkpoints[3],
            original,
            AdmissionPhase::NativeCompleted,
            previous.token.sequence,
        );
        observed(
            &evidence.successor,
            input.checkpoints[3],
            original,
            phase,
            Some(signal.clone()),
        );
        let Consumption::OwnedStack(records) = &evidence.evidence else {
            panic!("stack evidence kind differs")
        };
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.trace, Some(input.trace));
        assert_eq!(record.call, input.call_id);
        assert_eq!(
            record.words,
            Some(input.words.captures.map(|v| v.word.bytes))
        );
        let binding = record.binding.as_ref().unwrap();
        assert_eq!(binding.census, self.identity);
        assert_eq!(binding.reservation, input.reservation);
        assert_eq!(binding.origin, identity.origin());
        assert_eq!(binding.execution, identity.execution());
        assert_eq!(binding.until, identity.until());
        assert_eq!(&binding.operand, identity.operand_description());
        assert_eq!(binding.profile.stack, identity.stack_descriptor());
        assert_eq!(binding.profile.metadata, identity.stack_metadata());
        assert_eq!(binding.profile.layout, identity.pku_layout());
        assert_eq!(binding.profile.initial_rsp, identity.initial_rsp());
        assert_eq!(&binding.profile.restored, identity.initial_stop());
        assert_eq!(binding.source.id, identity.source_id());
        let window = input.sources.window(identity.source_id().index()).unwrap();
        assert_eq!(binding.source, SourceRecord::capture(&window));
        assert_eq!(binding.source.initial, window.initial_source());
        assert_eq!(binding.source.range, window.snapshot.range());
        assert_eq!(binding.source.target, window.target);
        let geometry = &binding.operand.geometry;
        assert_eq!(binding.fetch.instruction().start(), geometry.pc);
        assert_eq!(binding.fetch.instruction().end(), geometry.next_pc);
        let offset = usize::try_from(geometry.pc - window.snapshot.range().start()).unwrap();
        assert_eq!(
            &window.snapshot.bytes()[offset..offset + geometry.length],
            &geometry.encoding[..geometry.length]
        );
        assert_eq!(input.trace.ordinal, 3);
        assert_eq!(input.trace.tid, original.token.tid);
        assert!(libc::WIFSTOPPED(input.trace.status));
        assert_eq!(libc::WSTOPSIG(input.trace.status), libc::SIGTRAP);
        assert_eq!(input.trace.status >> 16, 0);
        assert_eq!(input.trace.dr6, 0xffff_4ff0);
        let info = &signal;
        assert_eq!(info.signal(), libc::SIGTRAP);
        assert_eq!(info.errno(), 0);
        assert_eq!(info.code(), libc::TRAP_TRACE);
        assert_eq!(
            u64::from_ne_bytes(input.trace.signal[16..24].try_into().unwrap()),
            input.checkpoints[3].state.registers.rip
        );
        words(&input, binding);
        previous = &evidence.successor;
        for (index, record) in history[4..].iter().enumerate() {
            let HistoryRecord::Refreshed {
                origin,
                before,
                after,
            } = record
            else {
                panic!("stack closing missing")
            };
            assert_eq!(*origin, input.current);
            assert_eq!(before, previous);
            assert_eq!(before.xstate.capacity(), MAX_XSTATE_BYTES);
            checkpoint_identity(
                input.checkpoints[index + 4],
                original,
                AdmissionPhase::Restored,
                before.token.sequence,
            );
            assert_eq!(
                input.checkpoints[index + 4].state,
                input.checkpoints[3].state
            );
            observed(
                after,
                input.checkpoints[index + 4],
                original,
                StopPhase::UserCheckpoint,
                None,
            );
            previous = after;
        }
        let old = self
            .state
            .origins
            .iter()
            .find(|v| v.row.id == identity.origin())
            .unwrap();
        assert!(!old.active);
        let active = self
            .state
            .origins
            .iter()
            .filter(|v| v.active)
            .collect::<Vec<_>>();
        assert_eq!(active.len(), 1);
        let current = active[0];
        assert_eq!(current.row.id, input.current);
        assert_eq!(input.current.census, self.identity);
        assert_eq!(input.current.serial, binding.candidate_serial);
        assert_eq!(self.state.next_serial, input.current.serial + 1);
        assert_eq!(current.row.kind, OriginKind::CurrentHeldPc);
        assert_eq!(current.row.created_generation, 0);
        assert_eq!(current.row.pc, input.checkpoints[3].state.registers.rip);
        assert_eq!(&current.row.initial, &evidence.successor);
        assert_eq!(current.row.initial.xstate.capacity(), MAX_XSTATE_BYTES);
        assert_eq!(&current.current, previous);
        assert_eq!(current.current.xstate.capacity(), MAX_XSTATE_BYTES);
        assert!(current.frame.is_none() && current.runtime_kernel.is_none());
        assert_eq!(input.native_current, input.checkpoints[6].stop);
        assert_eq!(current.current.token, input.native_current.token);
        assert_eq!(current.current.task, input.native_current.identity);
        assert_eq!(
            current.current.registers,
            input.checkpoints[6].state.registers
        );
        assert_eq!(current.current.xstate, input.checkpoints[6].state.xstate);
        assert_eq!(current.current.signal_mask, input.checkpoints[6].state.mask);
        self.test_stack_snapshot()
    }
    /// No live authority or clock check: safe to repeat after physical cleanup.
    /// State values are complete typed clones; capacities/pointers are captured
    /// separately because Vec::clone does not retain the original capacity.
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_stack_snapshot(
        &self,
    ) -> StackCensusSnapshot {
        let mut stack_payloads = Vec::new();
        for (index, record) in self.state.history.iter().enumerate() {
            match record {
                HistoryRecord::Refreshed { before, after, .. } => {
                    stack_payloads.push((
                        index,
                        vec![allocation(&before.xstate), allocation(&after.xstate)],
                        None,
                    ));
                }
                HistoryRecord::Consumed { evidence, .. } => {
                    if let Consumption::OwnedStack(records) = &evidence.evidence {
                        stack_payloads.push((
                            index,
                            vec![
                                allocation(&evidence.before.xstate),
                                allocation(&evidence.successor.xstate),
                            ],
                            Some((records.as_ptr() as usize, records.len())),
                        ));
                    }
                }
                _ => {}
            }
        }
        StackCensusSnapshot {
            identity: self.identity,
            session: self.session,
            space: self.space,
            limits: self.limits,
            state: self.state.clone(),
            origins_address: self.state.origins.as_ptr() as usize,
            origins_capacity: self.state.origins.capacity(),
            history_address: self.state.history.as_ptr() as usize,
            history_capacity: self.state.history.capacity(),
            origin_payloads: self
                .state
                .origins
                .iter()
                .map(|v| {
                    [
                        allocation(&v.row.initial.xstate),
                        allocation(&v.current.xstate),
                    ]
                })
                .collect(),
            stack_payloads,
        }
    }
}

impl ResumeCensus {
    /// Copied-data Eq sensitivity only. No budget, permit or native eligibility
    /// is changed; every mutation starts from this actual retained snapshot.
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_stack_snapshot_sensitivity(
        &self,
    ) {
        let original = self.test_stack_snapshot();
        assert_eq!(original, self.test_stack_snapshot());
        let axes: [(&str, fn(&mut BudgetCharge)); 6] = [
            ("epochs", |value| value.epochs ^= 1),
            ("source_fact_bytes", |value| value.source_fact_bytes ^= 1),
            ("reports", |value| value.reports ^= 1),
            ("origins", |value| value.origins ^= 1),
            ("witnesses", |value| value.witnesses ^= 1),
            ("plan_history", |value| value.plan_history ^= 1),
        ];
        for (axis, corrupt) in axes {
            for charged in [false, true] {
                let mut changed = original.clone();
                corrupt(if charged {
                    &mut changed.state.charged
                } else {
                    &mut changed.state.used
                });
                assert_ne!(
                    changed, original,
                    "copied budget: {axis}, charged={charged}"
                );
                assert_eq!(self.test_stack_snapshot(), original);
            }
        }
        let limits: [(&str, fn(&mut Limits)); 6] = [
            ("epochs", |value| value.epochs ^= 1),
            ("source_fact_bytes", |value| value.source_fact_bytes ^= 1),
            ("reports", |value| value.reports ^= 1),
            ("origins", |value| value.origins ^= 1),
            ("witnesses", |value| value.witnesses ^= 1),
            ("plan_history", |value| value.plan_history ^= 1),
        ];
        for (axis, corrupt) in limits {
            let mut changed = original.clone();
            corrupt(&mut changed.limits);
            assert_ne!(changed, original, "copied limit: {axis}");
            assert_eq!(self.test_stack_snapshot(), original);
        }
    }
}
