use super::*;
use std::cell::Cell;
use std::rc::Rc;

#[test]
fn stack_exact_owners_preserve_capacity_alignment_drop_and_overflow() {
    struct DropCount(Rc<Cell<usize>>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let counter = Rc::new(Cell::new(0));
    let mut slots = exact_storage::empty_slots::<DropCount>(3).unwrap();
    assert_eq!(slots.len(), 3);
    assert!(slots.iter().all(Option::is_none));
    slots[1] = Some(exact_storage::value(DropCount(Rc::clone(&counter))).unwrap());
    assert_eq!(counter.get(), 0);
    drop(slots);
    assert_eq!(counter.get(), 1);
    assert!(exact_storage::empty_slots::<u8>(0).unwrap().is_empty());
    #[repr(align(128))]
    struct AlignedZero;
    let zero = exact_storage::value(AlignedZero).unwrap();
    assert_eq!((&*zero as *const AlignedZero as usize) % 128, 0);
    assert!(matches!(
        exact_storage::empty_slots::<u8>(usize::MAX),
        Err(AllocationError::Capacity)
    ));
    let bytes = exact_storage::empty_bytes(BYTES).unwrap();
    assert_eq!(bytes.len(), 0);
    assert_eq!(bytes.capacity(), BYTES);
    assert_eq!(
        history_payload_bytes::<u64, u128>(3).unwrap(),
        6 * size_of::<Option<Box<u8>>>()
    );
    assert_eq!(history_payload_bytes::<u8, u8>(0), Ok(0));
    assert_eq!(
        history_payload_bytes::<u8, u8>(usize::MAX),
        Err(StackError::Capacity)
    );
    #[repr(align(128))]
    struct Aligned(u8);
    let value = exact_storage::value(Aligned(7)).unwrap();
    assert_eq!((&*value as *const Aligned as usize) % 128, 0);
    assert_eq!(value.0, 7);
}
#[test]
fn stack_empty_headers_allocate_exact_three_independent_payloads_without_observations() {
    let mut p = PreparedStackProfile::empty();
    let mut o = PreparedStackOperand::empty();
    assert_eq!(
        p.allocated_bytes().unwrap(),
        size_of::<PreparedStackProfile>()
    );
    assert_eq!(
        o.allocated_bytes().unwrap(),
        size_of::<PreparedStackOperand>()
    );
    p.allocate_payloads().unwrap();
    o.allocate_payloads().unwrap();
    assert_eq!(
        p.allocated_bytes().unwrap(),
        PreparedStackProfile::reservation_bytes().unwrap()
    );
    assert_eq!(
        o.allocated_bytes().unwrap(),
        PreparedStackOperand::reservation_bytes().unwrap()
    );
    for record in [&p.observation, &o.observation] {
        assert_eq!(
            record.allocated_bytes().unwrap(),
            StackObservationStorage::reservation_bytes().unwrap()
        );
        assert_eq!(record.payload_bytes().unwrap(), 3 * BYTES);
        assert_eq!(
            (
                record.smaps.len(),
                record.maps.len(),
                record.state.state.xstate.len()
            ),
            (BYTES, BYTES, BYTES)
        );
        assert_ne!(record.smaps.as_ptr(), record.maps.as_ptr());
        assert_ne!(record.maps.as_ptr(), record.state.state.xstate.as_ptr());
        assert!(
            record
                .smaps
                .iter()
                .chain(&record.maps)
                .chain(&record.state.state.xstate)
                .all(|b| *b == 0)
        );
        assert_eq!(record.smaps_capture, FileCapture::default());
        assert_eq!(record.maps_capture, FileCapture::default());
        assert!(!record.state.complete);
        assert_eq!(record.state.registers_request, None);
        assert_eq!(record.state.xstate_request, None);
        assert_eq!(record.state.mask_request, None);
    }
    assert!(p.description().is_none());
    assert!(o.description().is_none());
    assert_eq!(p.allocate_payloads(), Err(StackError::Reused));
    assert_eq!(o.allocate_payloads(), Err(StackError::Reused));
}
#[test]
fn stack_each_allocation_failure_keeps_installed_prefix_and_first_error() {
    for failure in 0..3 {
        let mut p = exact_storage::value(PreparedStackProfile::empty()).unwrap();
        let address = (&*p) as *const PreparedStackProfile as usize;
        p.observation.set_fault(AllocationFault {
            fail_before: Some(failure),
            panic_after: None,
        });
        assert_eq!(p.allocate_payloads(), Err(StackError::Allocation));
        assert_eq!((&*p) as *const PreparedStackProfile as usize, address);
        let capacities = [
            p.observation.smaps.capacity(),
            p.observation.maps.capacity(),
            p.observation.state.state.xstate.capacity(),
        ];
        for (slot, capacity) in capacities.into_iter().enumerate() {
            assert_eq!(capacity, if slot < failure { BYTES } else { 0 });
        }
        for (slot, bytes) in [
            &p.observation.smaps,
            &p.observation.maps,
            &p.observation.state.state.xstate,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                p.observation.installed_pointers[slot],
                if slot < failure {
                    Some(bytes.as_ptr() as usize)
                } else {
                    None
                }
            );
            assert_eq!(bytes.len(), bytes.capacity());
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
        assert_eq!(
            p.allocated_bytes().unwrap(),
            size_of::<PreparedStackProfile>() + failure * BYTES
        );
        assert_eq!(p.observation.allocation.failed_slot, Some(failure));
        assert_eq!(p.first_failure(), Some(StackError::Allocation));
        p.mark_aborted();
        assert_eq!(p.first_failure(), Some(StackError::Allocation));
        assert_eq!(p.allocate_payloads(), Err(StackError::Reused));
        assert!(p.description().is_none());
        assert!(!p.observation.state.complete);
    }
}
#[test]
fn stack_each_installed_allocation_survives_caught_model_unwind() {
    for ordinal in 0..3 {
        let mut p = exact_storage::value(PreparedStackOperand::empty()).unwrap();
        let address = (&*p) as *const PreparedStackOperand as usize;
        p.observation.set_fault(AllocationFault {
            fail_before: None,
            panic_after: Some(ordinal),
        });
        let panic =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.allocate_payloads()));
        let payload = panic.unwrap_err();
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"owned stack allocation model unwind")
        );
        p.mark_aborted();
        assert_eq!((&*p) as *const PreparedStackOperand as usize, address);
        assert_eq!(
            p.allocated_bytes().unwrap(),
            size_of::<PreparedStackOperand>() + (ordinal + 1) * BYTES
        );
        assert_eq!(p.first_failure(), Some(StackError::Aborted));
        assert!(p.description().is_none());
        assert_eq!(p.observation.allocation.state, AllocationState::Aborted);
        assert_eq!(p.allocate_payloads(), Err(StackError::Reused));
        for (index, bytes) in [
            &p.observation.smaps,
            &p.observation.maps,
            &p.observation.state.state.xstate,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(bytes.capacity(), if index <= ordinal { BYTES } else { 0 });
            assert_eq!(
                p.observation.installed_pointers[index],
                if index <= ordinal {
                    Some(bytes.as_ptr() as usize)
                } else {
                    None
                }
            );
            assert_eq!(bytes.len(), bytes.capacity());
            assert!(bytes.iter().all(|b| *b == 0));
        }
    }
}
#[test]
fn stack_measured_capacity_tally_corruption_is_not_a_reservation_or_refund() {
    let mut storage = StackObservationStorage::empty();
    storage.allocate_payloads().unwrap();
    let full = storage.allocated_bytes().unwrap();
    for changed in [0, 3 * BYTES - 1, 3 * BYTES + 1, usize::MAX] {
        storage.allocation.retained_payload = changed;
        assert_eq!(storage.allocated_bytes(), Err(StackError::Capacity));
        assert_eq!(
            (
                storage.smaps.capacity(),
                storage.maps.capacity(),
                storage.state.state.xstate.capacity()
            ),
            (BYTES, BYTES, BYTES)
        );
    }
    storage.allocation.retained_payload = 3 * BYTES;
    assert_eq!(storage.allocated_bytes(), Ok(full));
    // Supplied-record corruption cannot make a nonconforming visible capacity
    // eligible merely by adjusting the measured tally to the same sum.
    let mut malformed = StackObservationStorage::empty();
    malformed.smaps = exact_storage::empty_bytes(BYTES - 1).unwrap();
    malformed.allocation.retained_payload = BYTES - 1;
    assert_eq!(malformed.allocated_bytes(), Err(StackError::Capacity));
}
