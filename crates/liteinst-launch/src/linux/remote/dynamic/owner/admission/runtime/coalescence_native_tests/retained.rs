//! Typed copies for equality after physical cleanup. These are test evidence,
//! not hashes standing in for payload equality or a native authority object.
use super::super::super::initial_coalescence::{InitialMapPlan, InitialMapProjection};
use super::super::super::runtime_capture::{PartialEntries, SourceWindowId};
use super::super::super::source_identity::{InitialSourceVma, SourceVma};
use super::*;
use crate::MemoryMapping;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct State {
    state: TaskStateSnapshot,
    requests: [Option<NativeRequest>; 3],
    pointer: (usize, usize),
    length: usize,
    capacity: usize,
    owned_pointer: usize,
    complete: bool,
}
fn state(slot: &StateSlot) -> State {
    State {
        state: slot.state.clone(),
        requests: [
            slot.registers_request,
            slot.xstate_request,
            slot.mask_request,
        ],
        pointer: (slot.requested_pointer, slot.returned_pointer),
        length: slot.returned_length,
        capacity: slot.state.xstate.capacity(),
        owned_pointer: slot.state.xstate.as_ptr() as usize,
        complete: slot.complete,
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Maps {
    bytes: Vec<u8>,
    length: usize,
    request: Option<NativeRequest>,
    filesystem: Option<i64>,
    complete: bool,
}
fn maps(map: &MapBuffer) -> Maps {
    Maps {
        bytes: map.bytes().to_vec(),
        length: map.length,
        request: map.request,
        filesystem: map.filesystem,
        complete: map.complete,
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Call {
    wait: Option<(i32, i32)>,
    queries_started: bool,
    signal: ([u8; 128], Option<NativeRequest>),
    registers: Option<RegisterSnapshot>,
    requests: [Option<NativeRequest>; 3],
    mask: u64,
    returned_length: usize,
    result: Option<u64>,
    complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct PairEvidence {
    plan: InitialMapPlan,
    projection: Option<InitialMapProjection>,
    stage: InitialCoalescenceStage,
    failure: Option<InitialBootstrapFailureKind>,
    original: Vec<u8>,
    final_bytes: Vec<u8>,
    capacities: [usize; 5],
    reads: [SourceReadProgress; 2],
    maps: Vec<Option<Maps>>,
    states: Vec<State>,
    pointers: [usize; 5],
    descriptor_capacities: Vec<(usize, Option<usize>)>,
    stops: [Option<AdmissionStop>; 3],
    call: Call,
    pool: Vec<Option<MemoryMapping>>,
    output: Vec<MemoryMapping>,
    retired: Vec<MemoryMapping>,
    transferred: bool,
    successful: usize,
    reserved: usize,
    allocated: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Window {
    id: SourceWindowId,
    vma: SourceVma,
    initial: InitialSourceVma,
    target: (u64, u64),
    snapshot: liteinst_admission::scan::Snapshot,
    entries: PartialEntries,
    storage: Vec<u8>,
    capture: SourceReadProgress,
    recheck: SourceReadProgress,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Retained {
    until: Instant,
    stage: RuntimeStage,
    ready: bool,
    charge: BudgetCharge,
    source_failure: Option<super::super::super::runtime_capture::CaptureFailure>,
    source_original: Vec<u8>,
    original_progress: SourceReadProgress,
    source_current: Vec<u8>,
    current_progress: SourceReadProgress,
    vmas: Vec<SourceVma>,
    windows: Vec<Window>,
    q: Option<PairEvidence>,
    bootstrap_states: Vec<State>,
    bootstrap_maps: Vec<Maps>,
    bootstrap_payloads: Vec<TaskStateSnapshot>,
    bootstrap_capacities: Vec<usize>,
    bootstrap_pointers: Vec<usize>,
    descriptors: Option<(Vec<MemoryMapping>, Vec<MemoryMapping>)>,
    bootstrap_stop: Option<AdmissionStop>,
    registry: Option<crate::lifecycle::RegistrySnapshot>,
}

pub(super) fn capture(owner: &Owner) -> Retained {
    let runtime = owner.runtime.as_ref().unwrap();
    let q = runtime.coalescence.as_ref().map(|q| {
        let d = q.diagnostics();
        let call = d.call;
        PairEvidence {
            plan: *d.plan,
            projection: d.projection.copied(),
            stage: d.stage,
            failure: d.first_failure,
            original: d.original_bytes.to_vec(),
            final_bytes: d.final_bytes.to_vec(),
            capacities: [
                d.original_capacity,
                d.final_capacity,
                d.pool_capacity,
                d.output_capacity,
                d.retired_capacity,
            ],
            pointers: [
                d.original_bytes.as_ptr() as usize,
                d.final_bytes.as_ptr() as usize,
                d.pool.as_ptr() as usize,
                d.output.as_ptr() as usize,
                d.retired_descriptors.as_ptr() as usize,
            ],
            descriptor_capacities: d
                .pool
                .iter()
                .flatten()
                .chain(d.output)
                .chain(d.retired_descriptors)
                .map(|row| {
                    (
                        row.permissions.capacity(),
                        row.pathname.as_ref().map(String::capacity),
                    )
                })
                .collect(),
            reads: *d.read_progress,
            maps: d.maps.iter().map(|map| map.as_ref().map(maps)).collect(),
            states: d.states.iter().map(state).collect(),
            stops: [
                d.before_stop.cloned(),
                d.after_stop.cloned(),
                d.final_stop.cloned(),
            ],
            call: Call {
                wait: call.wait,
                queries_started: call.queries_started,
                signal: (call.signal.bytes, call.signal.request),
                registers: call.registers,
                requests: call.requests,
                mask: call.mask,
                returned_length: call.returned_length,
                result: call.result,
                complete: call.complete,
            },
            pool: d.pool.to_vec(),
            output: d.output.to_vec(),
            retired: d.retired_descriptors.to_vec(),
            transferred: d.output_transferred,
            successful: d.successful_payload_bytes,
            reserved: d.reserved_payload_bytes,
            allocated: q.allocated_bytes().unwrap(),
        }
    });
    let (bootstrap_states, bootstrap_maps, descriptors, bootstrap_stop) =
        runtime.bootstrap.as_ref().map_or_else(
            || (Vec::new(), Vec::new(), None, None),
            |prepared| {
                let d = prepared.diagnostics();
                let boot = prepared.completed();
                (
                    d.states.iter().map(state).collect(),
                    vec![maps(d.exit_maps), maps(d.current_maps)],
                    boot.map(|boot| (boot.original_executables.clone(), boot.mappings.clone())),
                    boot.map(|boot| boot.stop.clone()),
                )
            },
        );
    let (original, progress) = runtime.sources.original_maps();
    let bootstrap_payloads = runtime
        .bootstrap
        .as_ref()
        .and_then(PreparedInitialBootstrap::completed)
        .map(|boot| {
            vec![
                boot.evidence.exec_event.clone(),
                boot.evidence.exec_exit.clone(),
                boot.evidence.entry_trap.clone(),
                boot.evidence.restored_entry.clone(),
            ]
        })
        .unwrap_or_default();
    let bootstrap_capacities = runtime
        .bootstrap
        .as_ref()
        .and_then(PreparedInitialBootstrap::completed)
        .map(|boot| {
            vec![
                boot.evidence.exec_event.xstate.capacity(),
                boot.evidence.exec_exit.xstate.capacity(),
                boot.evidence.entry_trap.xstate.capacity(),
                boot.evidence.restored_entry.xstate.capacity(),
            ]
        })
        .unwrap_or_default();
    let bootstrap_pointers = runtime
        .bootstrap
        .as_ref()
        .and_then(PreparedInitialBootstrap::completed)
        .map(|boot| {
            vec![
                boot.evidence.exec_event.xstate.as_ptr() as usize,
                boot.evidence.exec_exit.xstate.as_ptr() as usize,
                boot.evidence.entry_trap.xstate.as_ptr() as usize,
                boot.evidence.restored_entry.xstate.as_ptr() as usize,
            ]
        })
        .unwrap_or_default();
    let (current, current_progress) = runtime.sources.quarantine_maps();
    let windows = (0..runtime.sources.window_count())
        .map(|index| {
            let view = runtime.sources.window(index).unwrap();
            let (storage, capture, recheck) = runtime.sources.window_progress(index).unwrap();
            Window {
                id: view.id,
                vma: *view.vma,
                initial: view.initial_source(),
                target: (view.target.start(), view.target.end()),
                snapshot: view.snapshot.clone(),
                entries: *view.entries,
                storage: storage.to_vec(),
                capture: *capture,
                recheck: *recheck,
            }
        })
        .collect();
    Retained {
        until: runtime.until,
        stage: runtime.stage,
        ready: runtime.ready_issued,
        charge: runtime.startup.charged(),
        source_failure: runtime.sources.failure(),
        source_original: original.to_vec(),
        original_progress: *progress,
        source_current: current.to_vec(),
        current_progress: *current_progress,
        vmas: runtime.sources.vmas().to_vec(),
        windows,
        q,
        bootstrap_states,
        bootstrap_maps,
        bootstrap_payloads,
        bootstrap_capacities,
        bootstrap_pointers,
        descriptors,
        bootstrap_stop,
        registry: runtime
            .native
            .as_ref()
            .map(NativeLifecycle::admission_snapshot),
    }
}

pub(super) fn after_cleanup(owner: &Owner, expected: &Retained) {
    assert_eq!(capture(owner), *expected);
}
