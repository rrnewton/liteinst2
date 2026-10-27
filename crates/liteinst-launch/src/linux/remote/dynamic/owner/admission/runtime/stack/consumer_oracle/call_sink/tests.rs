//! Pure local ownership/closure controls. No native owner is launched; no
//! gettid, successful callback, claimed TLS owner or cleanup flag is fabricated.
//! Actual claimed retirement/callback/fail-stop remain separate native controls.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn consumer_observer_sink_exact_shape_and_unclaimed_snapshot() {
    let mut sink = CallSink::empty();
    let expected = size_of::<CallSink>() + size_of::<ThreadSlot>() + size_of::<AtomicU64>();
    assert_eq!(sink.allocated_bytes(), Ok(expected));
    assert_eq!(
        CallSink::reservation_bytes(0),
        Err(SinkError::Census(CensusConsumerError::Mismatch))
    );
    assert_eq!(
        CallSink::reservation_bytes(usize::MAX),
        Err(SinkError::Census(CensusConsumerError::Capacity))
    );
    assert_eq!(
        CallSink::reservation_bytes(19).unwrap(),
        expected + size_of::<PreparedCallObservation>() + 65536 + 19
    );
    let before = sink.progress().unwrap();
    let returned = sink.with_snapshot(|value| {
        assert!(value.is_none());
        assert_eq!(sink.progress().unwrap(), before);
        Err::<(), SinkError>(SinkError::Capacity)
    });
    assert_eq!(returned, Ok(Err(SinkError::Capacity)));
    assert_eq!(sink.progress().unwrap(), before);
    sink.mark_aborted().unwrap();
    assert_eq!(sink.progress().unwrap(), before);
    assert_eq!(sink.allocated_bytes(), Ok(expected));
}
#[test]
fn consumer_observer_sink_thread_slot_reentry_is_sticky() {
    let local = ThreadSlot::empty();
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _first = local.enter().unwrap();
        assert!(local.busy.get());
        assert!(matches!(local.enter(), Err(SinkError::Borrowed)));
        assert_eq!(local.first_failure.get(), Some(SinkError::Borrowed));
        local.fail(SinkError::Capacity);
        assert_eq!(local.first_failure.get(), Some(SinkError::Borrowed));
        std::panic::panic_any(0x4f42_5431_u32);
    }))
    .unwrap_err();
    assert_eq!(*panic.downcast::<u32>().unwrap(), 0x4f42_5431);
    assert!(!local.busy.get());
    {
        let _later = local.enter().unwrap();
        assert_eq!(local.first_failure.get(), Some(SinkError::Borrowed));
        assert!(local.slot.borrow().observation.is_none());
    }
    assert!(!local.busy.get());
    assert!(!local.slot.borrow().ever_used); // local model cannot acquire a real claim
}
#[test]
fn consumer_observer_sink_slot_identity_is_exact() {
    // Slot alone carries descriptive IDs, not native authority; it has no TLS
    // owner and no descriptor/cleanup permit.
    let id = SinkIdentity {
        id: 9,
        host_tid: 11,
        owner_session: 13,
        application: 17,
    };
    let mut slot = Slot::empty();
    assert_eq!(slot.require(id), Err(SinkError::ForeignOwner));
    slot.identity = Some(id);
    assert_eq!(slot.require(id), Err(SinkError::ForeignOwner));
    slot.ever_used = true;
    assert_eq!(slot.require(id), Ok(()));
    for changed in [
        SinkIdentity { id: 10, ..id },
        SinkIdentity { host_tid: 12, ..id },
        SinkIdentity {
            owner_session: 14,
            ..id
        },
        SinkIdentity {
            application: 18,
            ..id
        },
    ] {
        assert_eq!(slot.require(changed), Err(SinkError::ForeignOwner));
    }
    assert_eq!(slot.identity, Some(id));
    assert!(slot.observation.is_none());
    assert!(!slot.retired && !slot.callback_started && !slot.callback_complete);
}
#[test]
fn consumer_observer_sink_install_entry_is_once_and_retirement_is_permanent() {
    let mut sink = CallSink::empty();
    sink.start_install().unwrap();
    assert!(sink.progress.install_started);
    assert!(sink.progress.thread.is_none() && sink.progress.identity.is_none());
    assert!(!sink.progress.claimed && sink.retained.is_none());
    assert_eq!(sink.start_install(), Err(SinkError::Reused));
    assert_eq!(sink.progress.first_failure, Some(SinkError::Reused));
    sink.mark_aborted().unwrap();
    assert_eq!(sink.progress.first_failure, Some(SinkError::Reused));

    // Exercise genuine empty-guard finish/retire code, not a fabricated flag.
    // No process or pin exists, so this does not qualify claimed retirement.
    let mut empty_owner = ArtifactOwner::empty();
    empty_owner.finish().unwrap();
    let mut retired = CallSink::empty();
    retired.retire_after_cleanup(&empty_owner).unwrap();
    assert!(retired.progress.retired);
    assert!(!retired.progress.install_started && !retired.progress.claimed);
    assert_eq!(retired.start_install(), Err(SinkError::Reused));
    assert!(!retired.progress.install_started && !retired.progress.claimed);
    assert!(retired.progress.thread.is_none() && retired.progress.identity.is_none());
    assert!(retired.retained.is_none());

    // Supplied retained-box state tests the third entry predicate without
    // manufacturing a claimed native/TLS owner or a physical cleanup receipt.
    let mut retained = CallSink::empty();
    retained.retained = Some(exact_storage::value(PreparedCallObservation::empty()).unwrap());
    let address = std::ptr::from_ref(retained.retained.as_deref().unwrap());
    assert_eq!(retained.start_install(), Err(SinkError::Reused));
    assert_eq!(
        std::ptr::from_ref(retained.retained.as_deref().unwrap()),
        address
    );
    assert!(!retained.progress.install_started && !retained.progress.claimed);
}
#[test]
fn consumer_observer_sink_incomplete_cleanup_refuses_without_retirement() {
    let mut owner = ArtifactOwner::empty();
    let mut sink = CallSink::empty();
    assert!(!owner.partial_view().cleanup_complete);
    assert_eq!(
        sink.retire_after_cleanup(&owner),
        Err(SinkError::CleanupIncomplete)
    );
    let first = sink.progress;
    assert_eq!(first.first_failure, Some(SinkError::CleanupIncomplete));
    assert!(!first.retired && !first.claimed && sink.retained.is_none());
    assert_eq!(
        sink.retire_after_cleanup(&owner),
        Err(SinkError::CleanupIncomplete)
    );
    assert_eq!(sink.progress, first);
    owner.finish().unwrap(); // actual no-owner branch; no native cleanup claim
    sink.retire_after_cleanup(&owner).unwrap();
    assert!(sink.progress.retired);
    assert_eq!(sink.start_install(), Err(SinkError::Reused));
    assert_eq!(
        sink.progress.first_failure,
        Some(SinkError::CleanupIncomplete)
    );
    assert!(!sink.progress.install_started && !sink.progress.claimed);
}
