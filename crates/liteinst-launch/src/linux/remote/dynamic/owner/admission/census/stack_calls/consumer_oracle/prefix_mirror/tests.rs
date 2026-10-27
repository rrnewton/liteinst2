//! Supplied optional-owner/prefix controls; no real RecordedCall, callback,
//! claimed TLS, native seal or cleanup_complete state is constructed here.
use super::super::super::super::runtime_stack::tests::model::{Model, seeded};
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
const W: usize = 8192;
const PANIC: u32 = 0x5052_4331;
#[derive(Clone, Copy)]
pub(super) struct Fault {
    pub(super) before: Option<usize>,
    pub(super) after: Option<usize>,
}
pub(super) fn before(fault: Option<Fault>, index: usize) -> Result<(), CensusConsumerError> {
    if fault.is_some_and(|value| value.before == Some(index)) {
        Err(CensusConsumerError::Allocation)
    } else {
        Ok(())
    }
}
pub(super) fn after(fault: Option<Fault>, index: usize) {
    if fault.is_some_and(|value| value.after == Some(index)) {
        std::panic::panic_any(PANIC);
    }
}
fn supplied() -> (Box<PreparedCallObservation>, Model) {
    let (mut census, origin) = seeded();
    let reservation = census.reserve(BudgetCharge::default()).unwrap();
    let model = Model::new(&census, reservation, origin, StackOperation::DirectCall);
    let mut source = PreparedCallObservation::empty();
    source.allocate_payloads(W).unwrap();
    let mut before = census.current_observation(origin).unwrap().clone();
    let mut bytes = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    bytes.extend_from_slice(&before.xstate);
    before.xstate = bytes;
    source.header = Some(CallHeader {
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
    source.capture.begin().unwrap();
    source.capture.filled = 1;
    source.source.extend_from_slice(&[4, 5, 6]);
    source.capture.filled = 2;
    copy_state(&before, &mut source.before, &mut source.buffer).unwrap();
    source.capture.filled = 3;
    source.capture.fail(CensusConsumerError::Mismatch);
    (Box::new(source), model)
}
fn mirror(source: Option<&PreparedCallObservation>) -> PreparedCallPrefixMirror {
    let mut out = PreparedCallPrefixMirror::empty();
    out.allocate_payloads(W).unwrap();
    out.capture(source).unwrap();
    out
}
#[test]
fn consumer_call_prefix_mirror_retains_both_allocation_error_and_unwind_prefixes() {
    assert_eq!(
        PreparedCallPrefixMirror::reservation_bytes(0),
        Err(CensusConsumerError::Mismatch)
    );
    assert_eq!(
        PreparedCallPrefixMirror::reservation_bytes(usize::MAX),
        Err(CensusConsumerError::Capacity)
    );
    assert_eq!(
        PreparedCallPrefixMirror::reservation_bytes(W).unwrap(),
        size_of::<PreparedCallPrefixMirror>() + MAX_XSTATE_BYTES + W
    );
    for index in 0..2 {
        for unwind in [false, true] {
            let mut out = PreparedCallPrefixMirror::empty();
            out.allocation_fault = Some(Fault {
                before: (!unwind).then_some(index),
                after: unwind.then_some(index),
            });
            if unwind {
                let payload =
                    catch_unwind(AssertUnwindSafe(|| out.allocate_payloads(W))).unwrap_err();
                assert_eq!(*payload.downcast::<u32>().unwrap(), PANIC);
            } else {
                assert_eq!(
                    out.allocate_payloads(W),
                    Err(CensusConsumerError::Allocation)
                );
            }
            let count = index + usize::from(unwind);
            assert_eq!(out.allocation.filled, count);
            assert!(!out.allocation.complete);
            let expected = if count == 0 {
                0
            } else {
                MAX_XSTATE_BYTES + if count == 2 { W } else { 0 }
            };
            assert_eq!(
                out.allocated_bytes().unwrap(),
                size_of::<PreparedCallPrefixMirror>() + expected
            );
            let a = out.before.identity();
            let b = BufferIdentity::of(&out.source);
            assert_eq!(a.capacity, if count > 0 { MAX_XSTATE_BYTES } else { 0 });
            assert_eq!(b.capacity, if count > 1 { W } else { 0 });
            assert_eq!(a.length, 0);
            assert_eq!(b.length, 0);
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
            assert_eq!(out.before.identity(), a);
            assert_eq!(BufferIdentity::of(&out.source), b);
        }
    }
}
#[test]
fn consumer_call_prefix_mirror_distinguishes_absence_and_same_box_transfer() {
    let mut absent = mirror(None);
    absent.require_preserved(None).unwrap();
    let (source, _model) = supplied();
    assert_eq!(
        absent.require_preserved(Some(&source)),
        Err(CensusConsumerError::Mismatch)
    );
    let progress = absent.capture;
    assert_eq!(absent.capture(None), Err(CensusConsumerError::Reused));
    absent.mark_aborted();
    assert_eq!(absent.capture, progress);
    let out = mirror(Some(&source));
    out.require_preserved(Some(&source)).unwrap();
    assert_eq!(
        out.require_preserved(None),
        Err(CensusConsumerError::Mismatch)
    );
    // Moving this actual supplied Box preserves its pointee/allocation address.
    // This is a Box ownership model, not a claimed TLS cleanup/retirement test.
    let mut first = Some(source);
    let second = first.take();
    assert!(first.is_none());
    out.require_preserved(second.as_deref()).unwrap();
    let mut source = second.unwrap();
    let mut other = Box::new(PreparedCallObservation::empty());
    std::mem::swap(&mut *source, &mut *other);
    assert_eq!(
        out.require_preserved(Some(&other)),
        Err(CensusConsumerError::Mismatch)
    );
    std::mem::swap(&mut *source, &mut *other);
    out.require_preserved(Some(&source)).unwrap();
}
#[test]
fn consumer_call_prefix_mirror_checks_failed_header_state_source_and_identity() {
    let (mut source, _model) = supplied();
    let out = mirror(Some(&source));
    assert!(!source.capture.complete);
    assert_eq!(
        source.capture.first_failure,
        Some(CensusConsumerError::Mismatch)
    );
    macro_rules! changed {
        ($field:expr, $value:expr) => {{
            let old = $field;
            $field = $value;
            assert_eq!(
                out.require_preserved(Some(&source)),
                Err(CensusConsumerError::Mismatch)
            );
            $field = old;
            out.require_preserved(Some(&source)).unwrap();
        }};
    }
    changed!(source.allocation.filled, 0);
    changed!(source.capture.first_failure, None);
    changed!(source.payload, 0);
    changed!(source.source_capacity, None);
    changed!(source.header.as_mut().unwrap().address, 0);
    changed!(
        source.header.as_mut().unwrap().binding.candidate_serial,
        999
    );
    changed!(
        source.header.as_mut().unwrap().binding.profile.initial_rsp,
        0
    );
    changed!(source.header.as_mut().unwrap().binding.operand.value, 999);
    changed!(
        source.header.as_mut().unwrap().binding.reservation,
        Reservation {
            census: 0,
            serial: 0
        }
    );
    changed!(source.header.as_mut().unwrap().id.serial, 0);
    changed!(source.header.as_mut().unwrap().before_allocation.length, 0);
    changed!(source.header.as_mut().unwrap().buffer_allocation.pointer, 0);
    changed!(source.header.as_mut().unwrap().allocation.complete, false);
    changed!(source.header.as_mut().unwrap().settled_bytes, 0);
    changed!(source.header.as_mut().unwrap().allocated_bytes, 0);
    changed!(source.before.as_mut().unwrap().registers.rax, 999);
    changed!(source.before.as_mut().unwrap().signal_mask, 999);
    source.before.as_mut().unwrap().xstate[0] ^= 1;
    assert_eq!(
        out.require_preserved(Some(&source)),
        Err(CensusConsumerError::Mismatch)
    );
    source.before.as_mut().unwrap().xstate[0] ^= 1;
    source.source[0] ^= 1;
    assert_eq!(
        out.require_preserved(Some(&source)),
        Err(CensusConsumerError::Mismatch)
    );
    source.source[0] ^= 1;
    out.require_preserved(Some(&source)).unwrap();
    let mut bytes = exact_storage::empty_bytes(W).unwrap();
    bytes.extend_from_slice(&source.source);
    let old = std::mem::replace(&mut source.source, bytes);
    assert_eq!(
        out.require_preserved(Some(&source)),
        Err(CensusConsumerError::Mismatch)
    );
    source.source = old;
    out.require_preserved(Some(&source)).unwrap();
}
#[test]
fn consumer_call_prefix_mirror_retains_zero_length_and_failed_copy_prefixes() {
    let empty = PreparedCallObservation::empty();
    let out = mirror(Some(&empty));
    out.require_preserved(Some(&empty)).unwrap();
    assert!(!empty.capture.started);
    assert!(out.capture.complete);
    let mut out = PreparedCallPrefixMirror::empty();
    assert_eq!(
        out.capture(Some(&empty)),
        Err(CensusConsumerError::Incomplete)
    );
    out.mark_aborted();
    assert_eq!(
        out.capture.first_failure,
        Some(CensusConsumerError::Incomplete)
    );
    assert_eq!(
        out.require_preserved(Some(&empty)),
        Err(CensusConsumerError::Incomplete)
    );
    let mut source = PreparedCallObservation::empty();
    source.allocate_payloads(W + 1).unwrap();
    source.source.extend_from_slice(&[1, 2, 3]);
    let mut out = PreparedCallPrefixMirror::empty();
    out.allocate_payloads(W).unwrap();
    let a = out.before.identity();
    let b = BufferIdentity::of(&out.source);
    assert_eq!(
        out.capture(Some(&source)),
        Err(CensusConsumerError::Mismatch)
    );
    assert_eq!(out.present, Some(true));
    assert!(out.header.is_some());
    assert_eq!(out.capture.filled, 2);
    assert_eq!(out.before.identity(), a);
    assert_eq!(BufferIdentity::of(&out.source), b);
    out.mark_aborted();
    assert_eq!(
        out.capture.first_failure,
        Some(CensusConsumerError::Mismatch)
    );
    assert_eq!(
        out.allocated_bytes().unwrap(),
        PreparedCallPrefixMirror::reservation_bytes(W).unwrap()
    );
}
