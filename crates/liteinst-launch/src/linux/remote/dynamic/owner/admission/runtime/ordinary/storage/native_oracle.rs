//! Actual retained root/native owners. These diagnostics neither resume nor mint stops.
use super::super::super::super::census::{
    AllocationCensusSnapshot, OrdinaryPreparationHistorySnapshot,
};
use super::super::super::super::runtime_capture::SourceWindowId;
use super::super::super::super::source_identity::SourceVma;
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::runtime) enum OrdinaryAllocationFault {
    Before(usize),
    After(usize),
    Boundary { point: usize, unwind: bool },
}
impl OrdinaryAllocationFault {
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn unwinds(self) -> bool {
        matches!(self, Self::After(_) | Self::Boundary { unwind: true, .. })
    }
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn reason(
        self,
    ) -> &'static str {
        match self {
            Self::Boundary { .. } => "injected ordinary preparation boundary failure",
            _ => "injected ordinary allocation failure",
        }
    }
    fn control(self) -> AllocationFault {
        match self {
            Self::Before(i) => AllocationFault {
                before: Some(i),
                ..AllocationFault::default()
            },
            Self::After(i) => AllocationFault {
                after: Some(i),
                ..AllocationFault::default()
            },
            Self::Boundary { point, unwind } => AllocationFault {
                point: Some((point, unwind)),
                ..AllocationFault::default()
            },
        }
    }
    fn prefix(self) -> usize {
        match self {
            Self::Before(i) => i,
            Self::After(i) => i + 1,
            Self::Boundary { point: 0 | 1, .. } => 2,
            Self::Boundary { .. } => STAGES,
        }
    }
    fn registered(self) -> bool {
        !matches!(
            self,
            Self::Before(0 | 1) | Self::After(0 | 1) | Self::Boundary { point: 0, .. }
        )
    }
}
impl PendingOrdinaryPreparation {
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn with_test_fault(
        mut self,
        fault: Option<OrdinaryAllocationFault>,
    ) -> Self {
        if let Some(fault) = fault {
            self.record.fault = fault.control();
        }
        self
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Bytes {
    pointer: usize,
    capacity: usize,
    bytes: Vec<u8>,
}
fn bytes(v: &Vec<u8>) -> Bytes {
    Bytes {
        pointer: v.as_ptr() as usize,
        capacity: v.capacity(),
        bytes: v.clone(),
    }
}
#[derive(Debug, Eq, PartialEq)]
struct Slots {
    pointer: usize,
    length: usize,
    capacity: usize,
    owners: Vec<usize>,
}
fn slots(v: &Vec<Box<RuntimeOrdinaryAttempt>>) -> Slots {
    Slots {
        pointer: v.as_ptr() as usize,
        length: v.len(),
        capacity: v.capacity(),
        owners: v
            .iter()
            .map(|a| &**a as *const RuntimeOrdinaryAttempt as usize)
            .collect(),
    }
}
#[derive(Debug, Eq, PartialEq)]
struct Attempt {
    address: usize,
    reservation: Reservation,
    stop: AdmissionStop,
    before: ObservedStop,
    prior: Bytes,
    checkpoint: ObservedStop,
    checkpoint_bytes: Bytes,
    checkpoint_stop: AdmissionStop,
    source: [Bytes; 3],
    progress: [SourceReadProgress; 3],
    identity: Bytes,
    native: runtime_native::NativeStorageSnapshot,
    allocation: AllocationRecord,
    prior_slots: Slots,
    census: OrdinaryPreparationHistorySnapshot,
    stage: AttemptStage,
    failed: bool,
    unwound: bool,
}
fn attempt(v: &RuntimeOrdinaryAttempt) -> Attempt {
    Attempt {
        address: v as *const RuntimeOrdinaryAttempt as usize,
        reservation: v.reservation,
        stop: v.stop.clone(),
        before: v.before.clone(),
        prior: bytes(&v.before.xstate),
        checkpoint: v.source.checkpoint.clone(),
        checkpoint_bytes: bytes(&v.source.checkpoint.xstate),
        checkpoint_stop: v.source.checkpoint_stop.clone(),
        source: std::array::from_fn(|i| bytes(&v.source.bytes[i])),
        progress: v.source.progress,
        identity: bytes(&v.source.identity),
        native: v.native.allocation_custody_snapshot(),
        allocation: v.allocation,
        prior_slots: slots(&v.prior_slots),
        census: v.census.history_snapshot().unwrap(),
        stage: v.stage,
        failed: v.failed,
        unwound: v.unwound,
    }
}
#[derive(Debug, Eq, PartialEq)]
struct Pending {
    address: usize,
    record: AllocationRecord,
    stop: AdmissionStop,
    shape: (u64, u64),
    expected_capacity: usize,
    replacement: Option<Slots>,
    attempt: Option<Attempt>,
}
#[derive(Debug, Eq, PartialEq)]
struct Window {
    id: SourceWindowId,
    vma: SourceVma,
    target: (u64, u64),
    pointer: usize,
    bytes: Vec<u8>,
    capture: SourceReadProgress,
    recheck: SourceReadProgress,
}
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::runtime) struct OrdinaryAllocationSnapshot {
    until: Instant,
    stage: RuntimeStage,
    ready: bool,
    current_origin: Option<OriginId>,
    next_execution: u64,
    configured: Option<OrdinaryAllocationFault>,
    slots: Slots,
    attempts: Vec<Attempt>,
    pending: Option<Pending>,
    census: AllocationCensusSnapshot,
    current: ObservedStop,
    native_current: AdmissionStop,
    registry: crate::lifecycle::RegistrySnapshot,
    lineage: Option<runtime_native::ControlLineageSnapshot>,
    pages: Vec<RuntimePage>,
    windows: Vec<Window>,
    original_maps: Vec<u8>,
    original_progress: SourceReadProgress,
    baseline_maps: Vec<u8>,
    vmas: Vec<SourceVma>,
}
impl RuntimeOwner {
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn test_ordinary_allocation_fault(
        &mut self,
        fault: OrdinaryAllocationFault,
    ) -> Result<(), GateError> {
        let bounded = match fault {
            OrdinaryAllocationFault::Before(i) | OrdinaryAllocationFault::After(i) => i < STAGES,
            OrdinaryAllocationFault::Boundary { point, .. } => point < 6,
        };
        if !bounded
            || self.stage != RuntimeStage::Ready
            || self.ordinary_allocation_fault.is_some()
            || self.ordinary_preparation.is_some()
            || self.ordinary_attempts.last().is_some_and(|a| {
                a.stage != AttemptStage::Complete
                    || a.failed
                    || a.unwound
                    || a.allocation.first_failure.is_some()
            })
        {
            return Err(GateError::Refused(
                "ordinary test allocation selector is not ready",
            ));
        }
        self.ordinary_allocation_fault = Some(fault);
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn test_ordinary_allocation_snapshot(
        &self,
    ) -> OrdinaryAllocationSnapshot {
        let census = self.census.as_ref().unwrap();
        let current = census
            .current_observation(self.initial_origin.unwrap())
            .unwrap();
        let windows = (0..self.sources.window_count())
            .map(|i| {
                let w = self.sources.window(i).unwrap();
                let (_, capture, recheck) = self.sources.window_progress(i).unwrap();
                Window {
                    id: w.id,
                    vma: *w.vma,
                    target: (w.target.start(), w.target.end()),
                    pointer: w.snapshot.bytes().as_ptr() as usize,
                    bytes: w.snapshot.bytes().to_vec(),
                    capture: *capture,
                    recheck: *recheck,
                }
            })
            .collect();
        let (original_maps, original_progress) = self.sources.original_maps();
        OrdinaryAllocationSnapshot {
            until: self.until,
            stage: self.stage,
            ready: self.ready_issued,
            current_origin: self.initial_origin,
            next_execution: self.next_execution,
            configured: self.ordinary_allocation_fault,
            slots: slots(&self.ordinary_attempts),
            attempts: self.ordinary_attempts.iter().map(|v| attempt(v)).collect(),
            pending: self.ordinary_preparation.as_ref().map(|v| Pending {
                address: v as *const PendingOrdinaryPreparation as usize,
                record: v.record,
                stop: v.stop.clone(),
                shape: v.shape.allocation_shape_snapshot(),
                expected_capacity: v.expected_capacity,
                replacement: v.replacement.as_ref().map(slots),
                attempt: v.attempt.as_deref().map(attempt),
            }),
            census: census.allocation_custody_snapshot().unwrap(),
            current: current.clone(),
            native_current: self
                .native
                .as_ref()
                .unwrap()
                .admission_current(current.task.task)
                .unwrap(),
            registry: self.native.as_ref().unwrap().admission_snapshot(),
            lineage: self
                .control_lineage
                .as_ref()
                .map(|v| v.test_retained_snapshot()),
            pages: self.pages.clone(),
            windows,
            original_maps: original_maps.to_vec(),
            original_progress: *original_progress,
            baseline_maps: self.sources.runtime_baseline_maps().unwrap().to_vec(),
            vmas: self.sources.vmas().to_vec(),
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn test_require_ordinary_failure(
        &self,
        before: &OrdinaryAllocationSnapshot,
        fault: OrdinaryAllocationFault,
        until: Instant,
    ) {
        let after = self.test_ordinary_allocation_snapshot();
        assert_eq!(before.configured, None);
        assert_eq!(after.configured, None);
        assert_eq!(after.until, until);
        assert_eq!(before.until, until);
        assert_eq!(
            (after.stage, after.ready, after.current_origin),
            (before.stage, before.ready, before.current_origin)
        );
        assert_eq!(after.next_execution, before.next_execution + 1);
        assert_eq!(after.current, before.current);
        assert_eq!(after.native_current, before.native_current);
        assert_eq!(after.registry, before.registry);
        assert_eq!(after.lineage, before.lineage);
        assert_eq!(after.pages, before.pages);
        assert_eq!(after.windows, before.windows);
        assert_eq!(after.original_maps, before.original_maps);
        assert_eq!(after.original_progress, before.original_progress);
        assert_eq!(after.baseline_maps, before.baseline_maps);
        assert_eq!(after.vmas, before.vmas);
        assert!(before.pending.is_none());
        let old_count = before.attempts.len();
        assert_eq!(after.attempts[..old_count], before.attempts);
        let registered = fault.registered();
        assert_eq!(after.pending.is_none(), registered);
        assert_eq!(after.attempts.len(), old_count + usize::from(registered));
        assert_eq!(before.slots.length, before.slots.capacity);
        let end = fault.prefix();
        let capacity = before.slots.capacity + 1;
        let (record, actual) = if let Some(p) = &after.pending {
            assert_eq!(p.stop, before.native_current);
            assert_eq!(
                p.shape,
                (
                    before.current.logical_pc & !4095,
                    (before.current.logical_pc & !4095) + 4096
                )
            );
            assert_eq!(p.expected_capacity, capacity);
            assert_eq!(after.slots, before.slots);
            assert_eq!(p.replacement.is_some(), end >= 1);
            if let Some(s) = &p.replacement {
                assert_eq!((s.length, s.capacity), (0, capacity));
                assert!(s.owners.is_empty());
            }
            (&p.record, p.attempt.as_ref())
        } else {
            assert_eq!(
                (after.slots.length, after.slots.capacity),
                (old_count + 1, capacity)
            );
            assert_eq!(after.slots.owners[..old_count], before.slots.owners);
            let a = after.attempts.last().unwrap();
            assert_eq!(a.prior_slots.pointer, before.slots.pointer);
            assert_eq!(
                (a.prior_slots.length, a.prior_slots.capacity),
                (0, before.slots.capacity)
            );
            assert!(a.prior_slots.owners.is_empty());
            (&a.allocation, Some(a))
        };
        assert_eq!(actual.is_some(), end >= 2);
        assert_eq!(record.fault, fault.control());
        assert_eq!(record.origin, before.current_origin.unwrap());
        assert_eq!(record.serial, before.next_execution);
        assert_eq!(record.until, until);
        assert!(record.started);
        assert!(!record.allocated);
        let ordinal = match fault {
            OrdinaryAllocationFault::Before(i) | OrdinaryAllocationFault::After(i) => i,
            OrdinaryAllocationFault::Boundary { point: 0 | 1, .. } => 1,
            _ => 22,
        };
        assert_eq!(record.ordinal, Some(ordinal));
        let expected_failure = if fault.unwinds() {
            Failure::Unwound
        } else {
            Failure::Refused(fault.reason())
        };
        assert_eq!(record.first_failure, Some(expected_failure));
        assert_eq!(record.measurement_failure, None);
        assert_eq!(record.settlement_failure, None);
        assert_eq!(record.finish, Some(Ok(())));
        let copied = match fault {
            OrdinaryAllocationFault::Boundary { point: 2, .. } => [before.current.xstate.len(), 0],
            OrdinaryAllocationFault::Boundary { point: 3..=5, .. } => {
                [before.current.xstate.len(); 2]
            }
            _ => [0; 2],
        };
        assert_eq!(record.copied, copied);
        assert_eq!(record.temporary, root_temporary_bytes().unwrap());
        assert_eq!(record.window_bytes, 8192);
        assert_eq!(record.new_slots, if end >= 1 { capacity } else { 0 });
        if end >= 1 {
            let pointer = if registered {
                after.slots.pointer
            } else {
                after
                    .pending
                    .as_ref()
                    .unwrap()
                    .replacement
                    .as_ref()
                    .unwrap()
                    .pointer
            };
            assert_eq!(record.new_slots_pointer, pointer);
        } else {
            assert_eq!(record.new_slots_pointer, 0);
        }
        let payload = (2..end)
            .map(|i| match i {
                2 | 7 | 8..=16 => MAX_XSTATE,
                3..=5 => 8192,
                6 | 17..=22 => MAP_BYTES,
                _ => unreachable!(),
            })
            .sum::<usize>();
        let components = [
            record.temporary,
            if end >= 1 {
                capacity * size_of::<Box<RuntimeOrdinaryAttempt>>()
            } else {
                0
            },
            if end >= 2 {
                size_of::<RuntimeOrdinaryAttempt>()
            } else {
                0
            },
            payload,
        ];
        assert_eq!(record.settled, components);
        let mut charge = census::ordinary_shared_census_charge().unwrap();
        charge.source_fact_bytes += size_of::<RuntimeOrdinaryAttempt>()
            + 11 * MAX_XSTATE
            + 7 * MAP_BYTES
            + 3 * 8192
            + capacity * size_of::<Box<RuntimeOrdinaryAttempt>>()
            + record.temporary;
        self.census
            .as_ref()
            .unwrap()
            .require_allocation_failure_accounting(
                &before.census,
                record.reservation,
                charge,
                components.into_iter().sum(),
            );
        if let Some(a) = actual {
            assert_eq!(a.reservation, record.reservation);
            assert_eq!(a.stop, before.native_current);
            assert_eq!(a.checkpoint_stop, before.native_current);
            assert_eq!(a.stage, AttemptStage::Allocated);
            assert!(a.failed);
            assert_eq!(a.unwound, fault.unwinds());
            assert_eq!(
                a.census,
                SharedOrdinaryPreparation::empty()
                    .history_snapshot()
                    .unwrap()
            );
            for p in &a.progress {
                assert_eq!(*p, SourceReadProgress::default());
            }
            require_observation(&a.before, &a.prior, &before.current, end > 2, copied[0]);
            require_observation(
                &a.checkpoint,
                &a.checkpoint_bytes,
                &before.current,
                end > 7,
                copied[1],
            );
            for (i, s) in a.source.iter().enumerate() {
                require_zero(s, if end > i + 3 { 8192 } else { 0 });
            }
            require_zero(&a.identity, if end > 6 { MAP_BYTES } else { 0 });
            let converted = matches!(fault, OrdinaryAllocationFault::Boundary { point: 5, .. });
            a.native
                .require_unstarted(end.saturating_sub(8), converted, fault.unwinds(), until);
        }
    }
}
fn require_zero(v: &Bytes, capacity: usize) {
    assert_eq!(v.capacity, capacity);
    assert_eq!(v.bytes.len(), capacity);
    assert!(v.bytes.iter().all(|b| *b == 0));
}
fn require_observation(
    value: &ObservedStop,
    owner: &Bytes,
    original: &ObservedStop,
    allocated: bool,
    copied: usize,
) {
    let mut expected = original.clone();
    expected.xstate = if copied != 0 {
        original.xstate.clone()
    } else if allocated {
        vec![0; MAX_XSTATE]
    } else {
        Vec::new()
    };
    assert_eq!(*value, expected);
    assert_eq!(owner.bytes, value.xstate);
    assert_eq!(owner.capacity, if allocated { MAX_XSTATE } else { 0 });
    if copied != 0 {
        assert_eq!(copied, original.xstate.len());
    }
}
