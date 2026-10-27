//! Complete typed copies of both native owning variants, never a completion seal.
use super::super::profile::ProfileSnapshot;
use super::*;

#[derive(Debug, Eq, PartialEq)]
struct StateSnapshot {
    address: usize,
    allocation: (usize, usize, usize),
    state: TaskStateSnapshot,
    requests: [Option<Request>; 3],
    requested: usize,
    returned: usize,
    length: usize,
    complete: bool,
}
fn state(value: &StateSlot) -> StateSnapshot {
    StateSnapshot {
        address: value as *const StateSlot as usize,
        allocation: (
            value.state.xstate.as_ptr() as usize,
            value.state.xstate.len(),
            value.state.xstate.capacity(),
        ),
        state: value.state.clone(),
        requests: [
            value.registers_request,
            value.xstate_request,
            value.mask_request,
        ],
        requested: value.requested_pointer,
        returned: value.returned_pointer,
        length: value.returned_length,
        complete: value.complete,
    }
}
#[derive(Debug, Eq, PartialEq)]
struct MapSnapshot {
    address: usize,
    allocation: usize,
    bytes: Vec<u8>,
    length: usize,
    request: Option<Request>,
    filesystem: Option<i64>,
    complete: bool,
}
fn maps(value: &MapBuffer) -> MapSnapshot {
    MapSnapshot {
        address: value as *const MapBuffer as usize,
        allocation: value.initialized_storage().as_ptr() as usize,
        bytes: value.initialized_storage().to_vec(),
        length: value.length,
        request: value.request,
        filesystem: value.filesystem,
        complete: value.complete,
    }
}
#[derive(Debug, Eq, PartialEq)]
struct ProgressSnapshot {
    phase: InstructionPhase,
    failure: Option<(InstructionPhase, InstructionFailure)>,
    waits: [Option<(i32, i32)>; WAITS],
    queries: [bool; WAITS],
    completed: bool,
    closed: bool,
    effects: [Option<InstructionEffectRecord>; EFFECTS],
    effects_len: usize,
}
fn progress(value: &InstructionProgress) -> ProgressSnapshot {
    ProgressSnapshot {
        phase: value.phase,
        failure: value.first_failure,
        waits: value.waits,
        queries: value.queries_started,
        completed: value.instruction_completed,
        closed: value.nx_closed,
        effects: value.effects,
        effects_len: value.effects_len,
    }
}
#[derive(Debug, Eq, PartialEq)]
struct MemorySnapshot {
    address: u64,
    requested: usize,
    copied: usize,
    last_word: [u8; 8],
    bytes: [u8; 68],
    request: Option<Request>,
    complete: bool,
}
fn memory(v: &MemoryObservation) -> MemorySnapshot {
    MemorySnapshot {
        address: v.address,
        requested: v.requested,
        copied: v.copied,
        last_word: v.last_word,
        bytes: v.bytes,
        request: v.last_request,
        complete: v.complete,
    }
}
#[derive(Debug, Eq, PartialEq)]
pub(super) struct ProfileOwnerSnapshot {
    address: usize,
    extent: usize,
    value: ProfileSnapshot,
}
pub(super) fn profile_snapshot(value: &ControlProfile) -> ProfileOwnerSnapshot {
    ProfileOwnerSnapshot {
        address: value as *const ControlProfile as usize,
        extent: size_of::<ControlProfile>(),
        value: value.test_retained_snapshot(),
    }
}
type DebugSnapshot = ([u64; 6], [Option<Request>; 6]);
#[derive(Debug, Eq, PartialEq)]
struct Header {
    address: usize,
    shape: (u64, u64),
    until: Instant,
    signals: Vec<([u8; 128], Option<Request>)>,
    debug: Vec<DebugSnapshot>,
    profile: Option<ProfileOwnerSnapshot>,
    memory: MemorySnapshot,
    progress: ProgressSnapshot,
    initial: Option<AdmissionStop>,
    stops: [Option<AdmissionStop>; WAITS],
    source: Option<SourceWindowId>,
    origin: Option<OriginId>,
    execution: Option<ExecutionId>,
    encoding: [u8; 15],
    encoding_len: usize,
    trace: Option<NativeTrace>,
    claimed: bool,
}
#[derive(Debug, Eq, PartialEq)]
struct OwnerSnapshot {
    header: Header,
    states: Vec<Option<StateSnapshot>>,
    maps: Vec<Option<MapSnapshot>>,
    membership: Option<(usize, Vec<u8>)>,
}
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct NativeStorageSnapshot {
    address: usize,
    pending: Option<OwnerSnapshot>,
    allocated: Option<OwnerSnapshot>,
    next: usize,
    failure: Option<InstructionFailure>,
}
fn pending(v: &PendingInstructionStorage) -> OwnerSnapshot {
    OwnerSnapshot {
        header: Header {
            address: v as *const PendingInstructionStorage as usize,
            shape: (v.shape.fetch_start, v.shape.fetch_end),
            until: v.until,
            signals: v.signals.iter().map(|s| (s.bytes, s.request)).collect(),
            debug: v.debug.iter().map(|d| (d.values, d.requests)).collect(),
            profile: v.profile.as_deref().map(profile_snapshot),
            memory: memory(&v.peek),
            progress: progress(&v.progress),
            initial: v.initial.clone(),
            stops: v.stops.clone(),
            source: v.source,
            origin: v.origin,
            execution: v.execution,
            encoding: v.encoding,
            encoding_len: v.encoding_len,
            trace: v.trace,
            claimed: v.claimed,
        },
        states: v.states.iter().map(|s| s.as_ref().map(state)).collect(),
        maps: v.maps.iter().map(|s| s.as_ref().map(maps)).collect(),
        membership: v
            .membership
            .as_ref()
            .map(|b| (b.as_ptr() as usize, b.to_vec())),
    }
}
fn allocated(v: &PreparedInstructionAttempt) -> OwnerSnapshot {
    OwnerSnapshot {
        header: Header {
            address: v as *const PreparedInstructionAttempt as usize,
            shape: (v.shape.fetch_start, v.shape.fetch_end),
            until: v.until,
            signals: v.signals.iter().map(|s| (s.bytes, s.request)).collect(),
            debug: v.debug.iter().map(|d| (d.values, d.requests)).collect(),
            profile: Some(profile_snapshot(&v.profile)),
            memory: memory(&v.peek),
            progress: progress(&v.progress),
            initial: v.initial.clone(),
            stops: v.stops.clone(),
            source: v.source,
            origin: v.origin,
            execution: v.execution,
            encoding: v.encoding,
            encoding_len: v.encoding_len,
            trace: v.trace,
            claimed: v.claimed,
        },
        states: v.states.iter().map(|s| Some(state(s))).collect(),
        maps: v.maps.iter().map(|s| Some(maps(s))).collect(),
        membership: Some((v.membership.as_ptr() as usize, v.membership.to_vec())),
    }
}
impl NativeInstructionStorage {
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocation_custody_snapshot(
        &self,
    ) -> NativeStorageSnapshot {
        NativeStorageSnapshot {
            address: self as *const Self as usize,
            pending: match self.owner.as_ref() {
                Some(NativeStorageConversion::Partial(value)) => Some(pending(value)),
                _ => None,
            },
            allocated: match self.owner.as_ref() {
                Some(NativeStorageConversion::Allocated(value)) => Some(allocated(value)),
                _ => None,
            },
            next: self.next,
            failure: self.first_failure,
        }
    }
}
impl NativeStorageSnapshot {
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_unstarted(
        &self,
        count: usize,
        converted: bool,
        unwound: bool,
        until: Instant,
    ) {
        assert!(count <= 16);
        assert_eq!(self.next, count);
        assert_eq!(self.pending.is_some(), !converted);
        assert_eq!(self.allocated.is_some(), converted);
        assert_eq!(self.failure, unwound.then_some(InstructionFailure::Unwound));
        let v = if converted {
            self.allocated.as_ref().unwrap()
        } else {
            self.pending.as_ref().unwrap()
        };
        let h = &v.header;
        assert_eq!(h.until, until);
        assert_eq!(h.shape.1 - h.shape.0, 4096);
        assert_eq!(h.signals.len(), WAITS);
        assert!(h.signals.iter().all(|s| *s == ([0; 128], None)));
        assert_eq!(h.debug.len(), WAITS);
        assert!(h.debug.iter().all(|d| *d == ([0; 6], [None; 6])));
        assert_eq!(h.profile.is_some(), count == 16);
        if let Some(profile) = &h.profile {
            assert_ne!(profile.address, 0);
            assert_eq!(profile.address % std::mem::align_of::<ControlProfile>(), 0);
            assert_eq!(profile.extent, size_of::<ControlProfile>());
            profile.value.require_empty();
        }
        assert_eq!(
            h.memory,
            MemorySnapshot {
                address: 0,
                requested: 0,
                copied: 0,
                last_word: [0; 8],
                bytes: [0; 68],
                request: None,
                complete: false
            }
        );
        assert_eq!(h.progress.phase, InstructionPhase::Allocated);
        assert_eq!(
            h.progress.failure,
            unwound.then_some((InstructionPhase::Allocated, InstructionFailure::Unwound))
        );
        assert_eq!(h.progress.waits, [None; WAITS]);
        assert_eq!(h.progress.queries, [false; WAITS]);
        assert!(!h.progress.completed && !h.progress.closed);
        assert_eq!(h.progress.effects, [None; EFFECTS]);
        assert_eq!(h.progress.effects_len, 0);
        assert_eq!(h.initial, None);
        assert!(h.stops.iter().all(Option::is_none));
        assert_eq!((h.source, h.origin, h.execution), (None, None, None));
        assert_eq!(
            (h.encoding, h.encoding_len, h.trace, h.claimed),
            ([0; 15], 0, None, false)
        );
        assert_eq!(v.states.len(), STATES);
        for (i, value) in v.states.iter().enumerate() {
            assert_eq!(value.is_some(), i < count.min(STATES));
            if let Some(s) = value {
                assert_eq!((s.allocation.1, s.allocation.2), (MAX_XSTATE, MAX_XSTATE));
                assert!(s.state.xstate.iter().all(|b| *b == 0));
                let g = &s.state.registers;
                assert_eq!(
                    [
                        g.r15, g.r14, g.r13, g.r12, g.rbp, g.rbx, g.r11, g.r10, g.r9, g.r8, g.rax,
                        g.rcx, g.rdx, g.rsi, g.rdi, g.orig_rax, g.rip, g.cs, g.eflags, g.rsp, g.ss,
                        g.fs_base, g.gs_base, g.ds, g.es, g.fs, g.gs
                    ],
                    [0; 27]
                );
                assert_eq!(s.state.mask, 0);
                assert_eq!(s.requests, [None; 3]);
                assert_eq!(
                    (s.requested, s.returned, s.length, s.complete),
                    (0, 0, 0, false)
                );
            }
        }
        assert_eq!(v.maps.len(), 5);
        for (i, value) in v.maps.iter().enumerate() {
            assert_eq!(value.is_some(), i < count.saturating_sub(STATES).min(5));
            if let Some(m) = value {
                assert_eq!(m.bytes.len(), MAP_BYTES);
                assert!(m.bytes.iter().all(|b| *b == 0));
                assert_eq!(
                    (m.length, m.request, m.filesystem, m.complete),
                    (0, None, None, false)
                );
            }
        }
        assert_eq!(v.membership.is_some(), count >= 15);
        if let Some((_, bytes)) = &v.membership {
            assert_eq!(bytes.len(), MAP_BYTES);
            assert!(bytes.iter().all(|b| *b == 0));
        }
    }
}

impl InstructionAttemptShape {
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocation_shape_snapshot(
        self,
    ) -> (u64, u64) {
        (self.fetch_start, self.fetch_end)
    }
}
