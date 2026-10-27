//! Synthetic descriptor/state storage controls. No RecordedCall, production
//! RuntimeStackBinding, live source authority or native completion is created.
use super::super::super::runtime_stack::tests::model::{Model, seeded};
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime::maps::FetchGeometry;
use crate::linux::remote::dynamic::owner::admission::runtime_capture::SourceWindowId;
use crate::linux::remote::dynamic::owner::admission::runtime_stack::access::{
    CPUID_INPUTS, CpuidRecord, PkuLayoutEvidence,
};
use crate::linux::remote::dynamic::owner::admission::runtime_stack::metadata::validate_smaps;
use crate::linux::remote::dynamic::owner::admission::source_identity::InitialSourceVma;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;

const W: usize = 8192;
const PANIC: u32 = 0x4f42_4331;
#[derive(Clone, Copy)]
pub(super) struct Fault {
    pub(super) before: Option<usize>,
    pub(super) after: Option<usize>,
}
pub(super) fn before(fault: Option<Fault>, index: usize) -> Result<(), CensusConsumerError> {
    if fault.is_some_and(|f| f.before == Some(index)) {
        Err(CensusConsumerError::Allocation)
    } else {
        Ok(())
    }
}
pub(super) fn after(fault: Option<Fault>, index: usize) {
    if fault.is_some_and(|f| f.after == Some(index)) {
        std::panic::panic_any(PANIC);
    }
}
fn prefix(out: &PreparedCallObservation, count: usize) {
    let expected = match count {
        0 => 0,
        1 => MAX_XSTATE_BYTES,
        2 => MAX_XSTATE_BYTES + W,
        _ => panic!("bad model prefix"),
    };
    assert_eq!(out.payload, expected);
    assert_eq!(out.allocation.filled, count);
    assert_eq!(
        out.allocated_bytes().unwrap(),
        size_of::<PreparedCallObservation>() + expected
    );
    assert_eq!(
        out.buffer.capacity(),
        if count > 0 { MAX_XSTATE_BYTES } else { 0 }
    );
    assert_eq!(out.source.capacity(), if count > 1 { W } else { 0 });
    assert!(
        out.buffer.is_empty()
            && out.source.is_empty()
            && out.before.is_none()
            && out.header.is_none()
    );
}
fn supplied() -> (PreparedCallObservation, ObservedStop, Model) {
    let (mut census, origin) = seeded();
    let reservation = census.reserve(BudgetCharge::default()).unwrap();
    let model = Model::new(&census, reservation, origin, StackOperation::DirectCall);
    let mut before = census.current_observation(origin).unwrap().clone();
    let mut buffer = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    buffer.extend_from_slice(&before.xstate);
    before.xstate = buffer;
    let mut out = PreparedCallObservation::empty();
    out.allocate_payloads(W).unwrap();
    // This is a supplied comparison specimen, not an appended call record.
    out.header = Some(CallHeader {
        address: 0x1230,
        binding: model.binding.clone(),
        id: PotentialCallId {
            census: census.identity,
            session: census.session,
            ledger: 0x4560,
            serial: 1,
        },
        before_allocation: BufferIdentity::of(&before.xstate),
        buffer_allocation: BufferIdentity::of(&Vec::new()),
        allocation: PayloadProgress {
            started: true,
            complete: true,
            payload: MAX_XSTATE_BYTES,
            failure: None,
        },
        settled_bytes: size_of::<PreparedCallRecord>() + MAX_XSTATE_BYTES,
        allocated_bytes: size_of::<PreparedCallRecord>() + MAX_XSTATE_BYTES,
    });
    out.capture.begin().unwrap();
    out.capture.filled = 1;
    out.source.extend_from_slice(model.snapshot.bytes());
    out.capture.filled = 2;
    copy_state(&before, &mut out.before, &mut out.buffer).unwrap();
    out.capture.filled = 3;
    // Complete is intentionally false: only genuine RecordedCall/binding may
    // pass the real copy entrypoint, which these model controls never invoke.
    (out, before, model)
}
#[test]
fn consumer_observer_call_storage_exact_shape_and_reuse() {
    assert_eq!(
        PreparedCallObservation::reservation_bytes(0),
        Err(CensusConsumerError::Mismatch)
    );
    assert_eq!(
        PreparedCallObservation::reservation_bytes(usize::MAX),
        Err(CensusConsumerError::Capacity)
    );
    let mut ledger = RuntimeCallLedger::empty();
    assert_eq!(ledger.consumer_count(), 0);
    ledger.allocate_payloads(2).unwrap();
    assert_eq!(ledger.consumer_count(), 0);
    let mut out = PreparedCallObservation::empty();
    prefix(&out, 0);
    out.allocate_payloads(W).unwrap();
    prefix(&out, 2);
    assert_eq!(
        PreparedCallObservation::reservation_bytes(W).unwrap(),
        size_of::<PreparedCallObservation>() + 65536 + W
    );
    let allocation = out.allocation;
    let a = BufferIdentity::of(&out.buffer);
    let b = BufferIdentity::of(&out.source);
    assert_eq!(out.allocate_payloads(W), Err(CensusConsumerError::Reused));
    out.mark_aborted();
    assert_eq!(out.allocation, allocation);
    assert_eq!(BufferIdentity::of(&out.buffer), a);
    assert_eq!(BufferIdentity::of(&out.source), b);
    assert!(!out.capture.started);
}
#[test]
fn consumer_observer_call_allocation_error_and_unwind_prefixes() {
    for index in 0..2 {
        for unwind in [false, true] {
            let mut out = PreparedCallObservation::empty();
            out.allocation_fault = Some(Fault {
                before: (!unwind).then_some(index),
                after: unwind.then_some(index),
            });
            if unwind {
                let panic =
                    catch_unwind(AssertUnwindSafe(|| out.allocate_payloads(W))).unwrap_err();
                assert_eq!(*panic.downcast::<u32>().unwrap(), PANIC);
            } else {
                assert_eq!(
                    out.allocate_payloads(W),
                    Err(CensusConsumerError::Allocation)
                );
            }
            prefix(&out, index + usize::from(unwind));
            assert_eq!(out.source_capacity, Some(W));
            let a = BufferIdentity::of(&out.buffer);
            let b = BufferIdentity::of(&out.source);
            assert!(!out.allocation.complete);
            out.mark_aborted();
            let first = out.allocation;
            assert_eq!(
                first.first_failure,
                Some(if unwind {
                    CensusConsumerError::Aborted
                } else {
                    CensusConsumerError::Allocation
                })
            );
            out.allocation.fail(CensusConsumerError::Capacity);
            assert_eq!(out.allocate_payloads(W), Err(CensusConsumerError::Reused));
            assert_eq!(out.allocation, first);
            assert_eq!(BufferIdentity::of(&out.buffer), a);
            assert_eq!(BufferIdentity::of(&out.source), b);
            prefix(&out, index + usize::from(unwind));
        }
    }
}
#[test]
fn consumer_observer_call_partial_copy_retains_header_state_and_source() {
    let (mut out, before, model) = supplied();
    assert_eq!(out.before.as_ref(), Some(&before));
    assert_eq!(out.source, model.snapshot.bytes());
    assert_eq!(out.buffer.capacity(), 0);
    assert_eq!(
        out.before.as_ref().unwrap().xstate.capacity(),
        MAX_XSTATE_BYTES
    );
    assert_eq!(
        out.allocated_bytes().unwrap(),
        PreparedCallObservation::reservation_bytes(W).unwrap()
    );
    let state = out.before.clone();
    let header = out.header.clone();
    let bytes = out.source.clone();
    let state_address = BufferIdentity::of(&out.before.as_ref().unwrap().xstate);
    let source_address = BufferIdentity::of(&out.source);
    out.capture.fail(CensusConsumerError::Mismatch);
    out.mark_aborted();
    out.capture.fail(CensusConsumerError::Capacity);
    assert_eq!(
        out.capture.first_failure,
        Some(CensusConsumerError::Mismatch)
    );
    assert_eq!(
        out.capture.require_complete(),
        Err(CensusConsumerError::Incomplete)
    );
    assert_eq!(out.before, state);
    assert_eq!(out.header, header);
    assert_eq!(out.source, bytes);
    assert_eq!(
        BufferIdentity::of(&out.before.as_ref().unwrap().xstate),
        state_address
    );
    assert_eq!(BufferIdentity::of(&out.source), source_address);
    assert!(!out.capture.complete);
}
#[test]
fn consumer_observer_call_header_projection_rejects_changed_record_families() {
    let (out, _, _) = supplied();
    let header = out.header.as_ref().unwrap();
    let view = out.partial_view();
    let projected = view.header.as_ref().unwrap();
    assert_eq!(projected.address, header.address);
    assert_eq!(projected.id, header.id);
    assert_eq!(projected.binding, ConsumerBindingView::of(&header.binding));
    assert_eq!(projected.before_allocation, header.before_allocation);
    assert_eq!(projected.buffer_allocation, header.buffer_allocation);
    assert_eq!(
        projected.allocation,
        ConsumerAllocationView::of(header.allocation)
    );
    assert_eq!(projected.settled_bytes, header.settled_bytes);
    assert_eq!(projected.allocated_bytes, header.allocated_bytes);
    type Mutation = fn(&mut CallHeader);
    let changes: &[Mutation] = &[
        |v| v.address ^= 1,
        |v| v.id.census ^= 1,
        |v| v.id.session ^= 1,
        |v| v.id.ledger ^= 1,
        |v| v.id.serial ^= 1,
        |v| v.binding.census ^= 1,
        |v| v.binding.reservation.serial ^= 1,
        |v| v.binding.candidate_serial ^= 1,
        |v| v.binding.reservation.census ^= 1,
        |v| v.binding.origin.census ^= 1,
        |v| v.binding.execution.session ^= 1,
        |v| {
            let mut identity = v.binding.source.id.identity();
            identity.mapping ^= 1;
            v.binding.source.id =
                SourceWindowId::synthetic_for_test(identity, v.binding.source.id.index());
        },
        |v| {
            let mut source = *v.binding.source.initial.source();
            source.offset ^= 4096;
            v.binding.source.initial = InitialSourceVma::strict(source);
        },
        |v| {
            v.binding.fetch = FetchGeometry::for_initial_source(
                v.binding.source.initial,
                AddressRange::new(0x401000, 0x401001).unwrap(),
            )
            .unwrap()
        },
        |v| v.binding.origin.serial ^= 1,
        |v| v.binding.execution.serial ^= 1,
        |v| v.binding.source.range = AddressRange::new(0x400000, 0x401000).unwrap(),
        |v| v.binding.source.target = AddressRange::new(0x400ffb, 0x401000).unwrap(),
        |v| v.binding.operand.value ^= 1,
        |v| v.binding.operand.target ^= 1,
        |v| v.binding.operand.pkru ^= 1,
        |v| v.binding.operand.geometry.next_pc ^= 1,
        |v| v.binding.operand.geometry.slot.start ^= 1,
        |v| v.binding.operand.geometry.encoding[1] ^= 1,
        |v| v.binding.operand.stop.token.sequence ^= 1,
        |v| v.binding.profile.stack.end ^= 4096,
        |v| v.binding.profile.initial_rsp ^= 8,
        |v| v.binding.profile.island.start ^= 4096,
        |v| v.binding.profile.restored.token.sequence ^= 1,
        |v| {
            v.binding.profile.metadata = validate_smaps(
            b"00800000-00804000 rw-p 00000000 00:00 0 [stack]\nProtectionKey: 0\nVmFlags: rd wr mr mw me gd ac\n",
            b"00800000-00804000 rw-p 00000000 00:00 0 [stack]\n", 0).unwrap()
        },
        |v| {
            let outputs = [
                [13, 0, 0, 0],
                [0, 0, (1 << 26) | (1 << 27), 0],
                [0, 0, (1 << 3) | (1 << 4), 0],
                [1 << 9, 0, 0, 0],
                [8, 896, 0, 0],
            ];
            v.binding.profile.layout = PkuLayoutEvidence {
                records: std::array::from_fn(|i| {
                    Some(CpuidRecord {
                        leaf: CPUID_INPUTS[i].0,
                        subleaf: CPUID_INPUTS[i].1,
                        registers: outputs[i],
                    })
                }),
            }
            .validate()
            .unwrap();
        },
        |v| v.binding.until += Duration::from_nanos(1),
        |v| v.binding.operand.until += Duration::from_nanos(1),
        |v| v.before_allocation.pointer ^= 1,
        |v| v.before_allocation.length ^= 1,
        |v| v.before_allocation.capacity ^= 1,
        |v| v.buffer_allocation.pointer ^= 1,
        |v| v.buffer_allocation.length ^= 1,
        |v| v.buffer_allocation.capacity ^= 1,
        |v| v.allocation.payload ^= 1,
        |v| v.allocation.started = false,
        |v| v.allocation.complete = false,
        |v| {
            v.allocation.failure =
                Some(super::super::super::runtime_stack::storage::StorageFailure::Aborted)
        },
        |v| v.settled_bytes ^= 1,
        |v| v.allocated_bytes ^= 1,
    ];
    for change in changes {
        let mut changed = header.clone();
        change(&mut changed);
        assert_ne!(*header, changed);
        let projected = CallHeaderView {
            address: changed.address,
            binding: ConsumerBindingView::of(&changed.binding),
            id: changed.id,
            before_allocation: changed.before_allocation,
            buffer_allocation: changed.buffer_allocation,
            allocation: ConsumerAllocationView::of(changed.allocation),
            settled_bytes: changed.settled_bytes,
            allocated_bytes: changed.allocated_bytes,
        };
        assert_ne!(out.partial_view().header.as_ref().unwrap(), &projected);
    }
    assert_eq!(out.partial_view(), out.partial_view());
    assert!(!out.capture.complete);
}
#[test]
fn consumer_observer_call_partial_view_compares_source_and_allocation_families() {
    let (out, _, model) = supplied();
    let source = model.binding.source.consumer_view();
    assert_eq!(source.id, model.binding.source.id);
    assert_eq!(source.initial, model.binding.source.initial);
    assert_eq!(source.range, model.snapshot.range());
    assert_eq!(source.target, model.binding.source.target);
    assert_eq!(source.before, model.snapshot.before);
    assert_eq!(source.after, model.snapshot.after);
    assert_eq!(source.writes, model.snapshot.writes);
    assert_eq!(
        source.snapshot_address,
        std::ptr::from_ref(&*model.snapshot) as usize
    );
    assert_eq!(
        source.bytes_address,
        model.snapshot.bytes().as_ptr() as usize
    );
    macro_rules! changed {
        ($body:expr) => {{
            let mut changed = out.partial_view();
            ($body)(&mut changed);
            assert_ne!(out.partial_view(), changed);
        }};
    }
    changed!(|v: &mut CallPartialView<'_>| v.address ^= 1);
    changed!(|v: &mut CallPartialView<'_>| v.payload ^= 1);
    changed!(|v: &mut CallPartialView<'_>| v.source_capacity = Some(W + 1));
    changed!(|v: &mut CallPartialView<'_>| v.source_allocation.pointer ^= 1);
    changed!(|v: &mut CallPartialView<'_>| v.source_allocation.length ^= 1);
    changed!(|v: &mut CallPartialView<'_>| v.source_allocation.capacity ^= 1);
    changed!(
        |v: &mut CallPartialView<'_>| v.copied_before_allocation.as_mut().unwrap().pointer ^= 1
    );
    changed!(|v: &mut CallPartialView<'_>| v.buffer_allocation.capacity ^= 1);
    changed!(
        |v: &mut CallPartialView<'_>| v.header.as_mut().unwrap().binding.source.before =
            liteinst_admission::scan::Boundary::NonExecutable
    );
    changed!(
        |v: &mut CallPartialView<'_>| v.header.as_mut().unwrap().binding.source.after =
            liteinst_admission::scan::Boundary::NonExecutable
    );
    changed!(
        |v: &mut CallPartialView<'_>| v.header.as_mut().unwrap().binding.source.writes =
            liteinst_admission::scan::WriteControl::ExternalWriter
    );
    changed!(|v: &mut CallPartialView<'_>| v
        .header
        .as_mut()
        .unwrap()
        .binding
        .source
        .snapshot_address ^= 1);
    changed!(|v: &mut CallPartialView<'_>| v
        .header
        .as_mut()
        .unwrap()
        .binding
        .source
        .bytes_address ^= 1);
    let mut bytes = out.source.clone();
    let mut changed = out.partial_view();
    changed.source = &bytes;
    assert_eq!(out.partial_view(), changed);
    bytes[17] ^= 1;
    let mut changed = out.partial_view();
    changed.source = &bytes;
    assert_ne!(out.partial_view(), changed);
    let mut before = out.before.as_ref().unwrap().clone();
    let mut changed = out.partial_view();
    changed.before = Some(&before);
    assert_eq!(out.partial_view(), changed);
    before.signal_mask ^= 1;
    let mut changed = out.partial_view();
    changed.before = Some(&before);
    assert_ne!(out.partial_view(), changed);
    let mut progress = out.capture;
    progress.filled ^= 1;
    let mut changed = out.partial_view();
    changed.capture = &progress;
    assert_ne!(out.partial_view(), changed);
}
