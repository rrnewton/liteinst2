//! Pure installed-owner and progress controls. No live task, CPUID, procfs,
//! ptrace call or successful native certificate is constructed here.
use super::super::super::runtime_stack::storage::{AllocationFault, AllocationState};
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

trait ModelOwner: Sized {
    fn empty() -> Self;
    fn storage(&self) -> &StackObservationStorage;
    fn storage_mut(&mut self) -> &mut StackObservationStorage;
    fn allocate(&mut self) -> Result<(), LaunchError>;
    fn abort(&mut self);
    fn bytes(&self) -> Result<usize, LaunchError>;
    fn progress(&self) -> &StackCaptureProgress;
}
macro_rules! model_owner {
    ($name:ty, $($field:ident).+) => {
        impl ModelOwner for $name {
            fn empty() -> Self { Self::empty() }
            fn storage(&self) -> &StackObservationStorage { &self.$($field).+ }
            fn storage_mut(&mut self) -> &mut StackObservationStorage { &mut self.$($field).+ }
            fn allocate(&mut self) -> Result<(), LaunchError> { self.allocate_payloads() }
            fn abort(&mut self) { self.mark_aborted(); }
            fn bytes(&self) -> Result<usize, LaunchError> { self.allocated_bytes() }
            fn progress(&self) -> &StackCaptureProgress { &self.progress }
        }
    };
}
model_owner!(PreparedStackProfileCapture, diagnostic.observation);
model_owner!(PreparedStackOperandCapture, diagnostic.observation);
model_owner!(NativeStackWordCapture, observation);
fn capacities(storage: &StackObservationStorage) -> [usize; 3] {
    [
        storage.smaps.capacity(),
        storage.maps.capacity(),
        storage.state.state.xstate.capacity(),
    ]
}
fn pointers(storage: &StackObservationStorage) -> [Option<usize>; 3] {
    [&storage.smaps, &storage.maps, &storage.state.state.xstate]
        .map(|bytes| (bytes.capacity() != 0).then_some(bytes.as_ptr() as usize))
}
fn verify_prefix<C: ModelOwner>(capture: &C, count: usize) {
    let storage = capture.storage();
    let expected = std::array::from_fn(|index| if index < count { BYTES } else { 0 });
    assert_eq!(capacities(storage), expected);
    assert_eq!(storage.allocation.retained_payload, count * BYTES);
    assert_eq!(capture.bytes().unwrap(), size_of::<C>() + count * BYTES);
    assert_eq!(pointers(storage), storage.installed_pointers);
    assert_eq!(storage.smaps.len(), expected[0]);
    assert_eq!(storage.maps.len(), expected[1]);
    assert_eq!(storage.state.state.xstate.len(), expected[2]);
    assert!(!storage.state.complete);
    assert_eq!(storage.smaps_capture, Default::default());
    assert_eq!(storage.maps_capture, Default::default());
}
#[test]
fn stack_native_empty_and_allocated_owners_never_issue_certificates() {
    let mut initial = PreparedStackProfileCapture::empty();
    let mut operand = PreparedStackOperandCapture::empty();
    let mut word = NativeStackWordCapture::empty();
    assert!(initial.identity().is_err());
    assert!(operand.operand().is_err());
    assert!(!word.attempted());
    verify_prefix(&initial, 0);
    verify_prefix(&operand, 0);
    verify_prefix(&word, 0);
    initial.allocate_payloads().unwrap();
    operand.allocate_payloads().unwrap();
    word.allocate_payloads().unwrap();
    verify_prefix(&initial, 3);
    verify_prefix(&operand, 3);
    verify_prefix(&word, 3);
    assert!(initial.identity().is_err());
    assert!(operand.operand().is_err());
    assert!(word.view().association.is_none());
    assert!(!word.view().complete);
    let saved = pointers(word.view().observation);
    assert!(word.allocate_payloads().is_err());
    assert_eq!(pointers(word.view().observation), saved);
    assert_eq!(
        word.allocated_bytes().unwrap(),
        size_of::<NativeStackWordCapture>() + 3 * BYTES
    );
}
fn allocation_failures<C: ModelOwner>() {
    for slot in 0..3 {
        let mut owner = C::empty();
        owner.storage_mut().set_fault(AllocationFault {
            fail_before: Some(slot),
            panic_after: None,
        });
        assert!(owner.allocate().is_err());
        verify_prefix(&owner, slot);
        assert_eq!(owner.storage().allocation.state, AllocationState::Failed);
        let saved = pointers(owner.storage());
        let first = owner.progress().first_failure;
        assert_eq!(
            first,
            Some((
                StackCaptureStage::Empty,
                StackCaptureFailure::Validation(StackError::Allocation)
            ))
        );
        assert!(owner.allocate().is_err());
        owner.abort();
        assert_eq!(owner.progress().first_failure, first);
        assert_eq!(pointers(owner.storage()), saved);
        verify_prefix(&owner, slot);
    }
}
#[test]
fn stack_native_each_wrapper_allocation_error_retains_exact_installed_prefix() {
    allocation_failures::<PreparedStackProfileCapture>();
    allocation_failures::<PreparedStackOperandCapture>();
    allocation_failures::<NativeStackWordCapture>();
}
fn allocation_unwinds<C: ModelOwner>() {
    for slot in 0..3 {
        let mut owner = C::empty();
        owner.storage_mut().set_fault(AllocationFault {
            fail_before: None,
            panic_after: Some(slot),
        });
        assert!(catch_unwind(AssertUnwindSafe(|| owner.allocate())).is_err());
        // The owner survived outside the caught scope. Root's live settlement
        // still requires its connected native oracle; this is allocator-only.
        let saved = pointers(owner.storage());
        owner.abort();
        verify_prefix(&owner, slot + 1);
        assert_eq!(owner.storage().allocation.state, AllocationState::Aborted);
        assert_eq!(
            owner.progress().first_failure,
            Some((StackCaptureStage::Empty, StackCaptureFailure::Unwound))
        );
        assert!(owner.allocate().is_err());
        assert_eq!(pointers(owner.storage()), saved);
        verify_prefix(&owner, slot + 1);
    }
}
#[test]
fn stack_native_each_wrapper_unwind_keeps_successful_capacity_without_refund() {
    allocation_unwinds::<PreparedStackProfileCapture>();
    allocation_unwinds::<PreparedStackOperandCapture>();
    allocation_unwinds::<NativeStackWordCapture>();
}
#[test]
fn stack_native_first_failure_survives_later_diagnostics_and_abort() {
    let mut progress = StackCaptureProgress::empty();
    progress.stage = StackCaptureStage::Smaps;
    let mut first = None;
    retain(
        &mut progress,
        &mut first,
        Err(LaunchError::System {
            operation: "synthetic first metadata read",
            source: std::io::Error::from_raw_os_error(libc::EFAULT),
        }),
    );
    progress.stage = StackCaptureStage::State;
    retain(&mut progress, &mut first, Ok(()));
    retain(
        &mut progress,
        &mut first,
        Err(LaunchError::Invalid("synthetic later state")),
    );
    progress.stage = StackCaptureStage::Maps;
    retain(
        &mut progress,
        &mut first,
        Err(LaunchError::Timeout("synthetic original deadline")),
    );
    progress.aborted();
    assert!(matches!(
        first,
        Some(LaunchError::System {
            operation: "synthetic first metadata read",
            ..
        })
    ));
    assert_eq!(
        progress.first_failure,
        Some((
            StackCaptureStage::Smaps,
            StackCaptureFailure::System("synthetic first metadata read", Some(libc::EFAULT))
        ))
    );
    let mut word = NativeStackWordCapture::empty();
    // A completed diagnostic phase must remain historical across a later
    // producer panic. This supplies no association, operand or native seal.
    word.progress.complete = true;
    word.progress.stage = StackCaptureStage::Complete;
    word.mark_aborted();
    assert!(word.view().complete);
    assert_eq!(word.view().first_failure, None);
    assert_eq!(word.view().association, None);
}
#[test]
fn stack_native_buffer_identity_survives_header_move_but_not_copy_or_resize() {
    let source = vec![7_u8; 32];
    let key = BufferIdentity::of(&source);
    let moved = source;
    assert_eq!(BufferIdentity::of(&moved), key);
    let copied = moved.clone();
    assert_eq!(moved, copied);
    assert_ne!(BufferIdentity::of(&copied), key);
    let mut shortened = moved;
    shortened.truncate(16);
    assert_ne!(BufferIdentity::of(&shortened), key);
    assert_eq!(shortened.as_ptr() as usize, key.pointer);
    assert_eq!(shortened.capacity(), key.capacity);
    for field in 0..3 {
        let mut bad = key;
        match field {
            0 => bad.pointer += 1,
            1 => bad.length += 1,
            _ => bad.capacity += 1,
        }
        assert_ne!(bad, key);
    }
}
#[test]
fn stack_native_capture_progress_rejects_unallocated_failed_and_repeated_entry() {
    let mut unallocated = StackCaptureProgress::empty();
    assert!(unallocated.begin().is_err());
    assert!(!unallocated.started);
    let mut allocated = StackCaptureProgress::empty();
    allocated.stage = StackCaptureStage::Allocated;
    allocated.begin().unwrap();
    assert!(allocated.started);
    assert_eq!(allocated.stage, StackCaptureStage::Authority);
    assert!(allocated.begin().is_err());
    let mut failed = StackCaptureProgress::empty();
    failed.stage = StackCaptureStage::Allocated;
    failed.fail(&LaunchError::Invalid("synthetic allocation refusal"));
    let saved = failed.first_failure;
    assert!(failed.begin().is_err());
    assert!(!failed.started);
    assert_eq!(failed.first_failure, saved);
    assert!(add(usize::MAX, 1).is_err());
}
