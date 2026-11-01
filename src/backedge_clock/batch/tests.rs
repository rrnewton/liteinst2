use super::*;
use crate::backedge_clock::{BackedgeClock, CLOCK_CANARY, CLOCK_PAGE_BYTES, ClockWords};
use std::cell::Cell;
use std::marker::PhantomData;
use std::ops::Deref;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, atomic::Ordering};

// Only private RW data pages are used here. No test enters generated/native
// code or forks the multithreaded harness. Completion is simulated protocol
// input; separate native controls must prove actual returned invocations.
struct Data(BackedgeClock);
impl Data {
    fn new() -> Self {
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                CLOCK_PAGE_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        Self(
            unsafe { BackedgeClock::from_owned_mapping(page as usize as u64, CLOCK_PAGE_BYTES) }
                .unwrap(),
        )
    }
}
impl Deref for Data {
    type Target = BackedgeClock;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for Data {
    fn drop(&mut self) {
        // All leases have dropped, and no execution occurred. Production has
        // no such recovery operation; clear only this test-owned data fixture
        // after asserting the failed paths retained active ownership.
        let storage = Arc::get_mut(&mut self.0.inner).expect("all simulated leases dropped");
        storage.pid = std::process::id();
        storage.active.store(false, Ordering::Release);
    }
}
fn snapshot(clock: &BackedgeClock) -> (ClockWords, [u8; CLOCK_PAGE_BYTES - 32]) {
    unsafe { clock.snapshot_parked() }
}
fn retained(clock: &BackedgeClock) {
    assert!(clock.inner.active.load(Ordering::Acquire));
    assert!(matches!(
        unsafe { clock.acquire(1, 1) },
        Err(ClockError::Owner)
    ));
}

#[test]
fn batch_precharges_exact_budget_and_finish_does_not_reset_words() {
    let clock = Data::new();
    let lease = unsafe { clock.acquire(64, 30) }.unwrap();
    assert_eq!(lease.admitted_work, 30);
    let before = snapshot(&clock);
    let mut batch = unsafe { lease.begin_batch(3, 10) }.unwrap();
    assert!(lease.in_call.get());
    assert!(matches!(lease.begin_call(), Err(ClockError::Invocation)));
    assert!(matches!(
        unsafe { lease.begin_batch(1, 1) },
        Err(ClockError::Invocation)
    ));
    assert_eq!(snapshot(&clock), before);
    for index in 0..3 {
        let token = batch.begin_call().unwrap();
        assert_eq!(token.batch.remaining_calls, 2 - index);
        assert_eq!(token.batch.remaining_work, 20 - index * 10);
        assert_eq!(token.batch.completed, index);
        assert!(token.batch.in_call && lease.in_call.get());
        // Simulated generated words make any accidental per-call reset
        // observable. The complete canary tail must remain untouched.
        let words = ClockWords {
            saved_rcx: 7 - index,
            encounters: 10 * (index + 1),
            counted: 9 * (index + 1),
            remaining: 64 - 9 * (index + 1),
        };
        unsafe { clock.inner.page.as_ptr().cast::<ClockWords>().write(words) };
        token.returned();
        assert_eq!(
            snapshot(&clock),
            (words, [CLOCK_CANARY; CLOCK_PAGE_BYTES - 32])
        );
    }
    assert!(matches!(batch.begin_call(), Err(ClockError::Invocation)));
    let final_words = snapshot(&clock);
    assert_eq!(batch.finish(), Ok(()));
    assert_eq!(lease.admission.get(), Admission::Finished);
    assert!(!lease.in_call.get());
    assert!(clock.inner.active.load(Ordering::Acquire));
    assert_eq!(snapshot(&clock), final_words);
    assert!(matches!(lease.begin_call(), Err(ClockError::Invocation)));
    assert!(matches!(
        unsafe { lease.begin_batch(1, 1) },
        Err(ClockError::Invocation)
    ));
    drop(lease);
    assert!(!clock.inner.active.load(Ordering::Acquire));
}

#[test]
fn batch_requires_positive_checked_product_within_exact_acquired_bound() {
    let clock = Data::new();
    let lease = unsafe { clock.acquire(7, 17) }.unwrap();
    let before = snapshot(&clock);
    for (calls, work) in [
        (0, 1),
        (1, 0),
        (0, 0),
        (3, 6),
        (1, MAX_WORK),
        (MAX_WORK + 1, 1),
        (u64::MAX, 2),
        (2, u64::MAX),
    ] {
        assert!(matches!(
            unsafe { lease.begin_batch(calls, work) },
            Err(ClockError::Invocation)
        ));
        assert_eq!(lease.admission.get(), Admission::Fresh);
        assert!(!lease.in_call.get());
        assert_eq!(snapshot(&clock), before);
    }
    let mut batch = unsafe { lease.begin_batch(2, 8) }.unwrap();
    batch.begin_call().unwrap().returned();
    batch.begin_call().unwrap().returned();
    assert_eq!(batch.finish(), Ok(()));
    drop(lease);
    // Exact ceiling is admitted, but the token still represents just one
    // simulated bounded call; no loop workload or generated entry runs here.
    let lease = unsafe { clock.acquire(1, MAX_WORK) }.unwrap();
    let mut batch = unsafe { lease.begin_batch(1, MAX_WORK) }.unwrap();
    batch.begin_call().unwrap().returned();
    assert_eq!(batch.finish(), Ok(()));
}

#[test]
fn batch_cannot_follow_ordinary_calls_and_old_reentry_still_refuses() {
    let clock = Data::new();
    let lease = unsafe { clock.acquire(5, 12) }.unwrap();
    let first = lease.begin_call().unwrap();
    assert_eq!(lease.admission.get(), Admission::Ordinary);
    assert!(matches!(lease.begin_call(), Err(ClockError::Invocation)));
    assert!(matches!(
        unsafe { lease.begin_batch(1, 1) },
        Err(ClockError::Invocation)
    ));
    assert!(lease.in_call.get());
    drop(first);
    assert!(!lease.in_call.get());
    drop(lease.begin_call().unwrap());
    assert!(matches!(
        unsafe { lease.begin_batch(1, 1) },
        Err(ClockError::Invocation)
    ));
    drop(lease);
    assert!(!clock.inner.active.load(Ordering::Acquire));
}

#[test]
fn forgotten_batch_token_keeps_persistent_outstanding_state() {
    let clock = Data::new();
    let lease = unsafe { clock.acquire(2, 4) }.unwrap();
    let mut batch = unsafe { lease.begin_batch(2, 2) }.unwrap();
    std::mem::forget(batch.begin_call().unwrap());
    assert_eq!(
        (batch.remaining_calls, batch.remaining_work, batch.completed),
        (1, 2, 0)
    );
    assert!(batch.in_call);
    assert!(matches!(batch.begin_call(), Err(ClockError::Invocation)));
    assert_eq!(batch.finish(), Err(ClockError::Invocation));
    assert!(lease.in_call.get());
    drop(lease);
    retained(&clock);
}

#[test]
fn dropped_batch_token_poison_cannot_be_completed_or_reused() {
    let clock = Data::new();
    let lease = unsafe { clock.acquire(2, 4) }.unwrap();
    let mut batch = unsafe { lease.begin_batch(2, 2) }.unwrap();
    drop(batch.begin_call().unwrap());
    assert!(batch.poisoned && batch.in_call);
    assert_eq!(batch.completed, 0);
    assert!(matches!(batch.begin_call(), Err(ClockError::Invocation)));
    assert_eq!(batch.finish(), Err(ClockError::Invocation));
    drop(lease);
    retained(&clock);
}

#[test]
fn incomplete_finish_and_abandoned_completed_batch_leave_lease_held() {
    for complete_without_finish in [false, true] {
        let clock = Data::new();
        let lease = unsafe { clock.acquire(2, 4) }.unwrap();
        let mut batch = unsafe { lease.begin_batch(2, 2) }.unwrap();
        batch.begin_call().unwrap().returned();
        if complete_without_finish {
            batch.begin_call().unwrap().returned();
            let _abandoned_without_finish = batch;
        } else {
            assert_eq!(batch.finish(), Err(ClockError::Invocation));
        }
        assert!(lease.in_call.get());
        assert_eq!(lease.admission.get(), Admission::Batch);
        assert!(matches!(lease.begin_call(), Err(ClockError::Invocation)));
        drop(lease);
        retained(&clock);
    }
}

#[test]
fn unwind_or_completion_called_from_unwind_cannot_release_batch() {
    struct CompleteOnDrop<'a, 'b>(Option<ClockBatchCall<'a, 'b>>);
    impl Drop for CompleteOnDrop<'_, '_> {
        fn drop(&mut self) {
            self.0.take().unwrap().returned();
        }
    }
    for complete_on_drop in [false, true] {
        let clock = Data::new();
        let lease = unsafe { clock.acquire(1, 1) }.unwrap();
        let mut batch = unsafe { lease.begin_batch(1, 1) }.unwrap();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let token = batch.begin_call().unwrap();
                if complete_on_drop {
                    let _completion = CompleteOnDrop(Some(token));
                    panic!("intentional simulated callback/host unwind");
                } else {
                    let _token = token;
                    panic!("intentional token unwind");
                }
            }))
            .is_err()
        );
        assert!(batch.poisoned && batch.in_call);
        assert_eq!(batch.completed, 0);
        assert_eq!(batch.finish(), Err(ClockError::Invocation));
        drop(lease);
        retained(&clock);
    }
}

#[test]
fn finish_during_unwind_cannot_clear_even_completed_batch() {
    struct FinishOnDrop<'a>(Option<ClockBatch<'a>>);
    impl Drop for FinishOnDrop<'_> {
        fn drop(&mut self) {
            assert_eq!(self.0.take().unwrap().finish(), Err(ClockError::Invocation));
        }
    }
    let clock = Data::new();
    let lease = unsafe { clock.acquire(1, 1) }.unwrap();
    let mut batch = unsafe { lease.begin_batch(1, 1) }.unwrap();
    batch.begin_call().unwrap().returned();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _finish = FinishOnDrop(Some(batch));
            panic!("intentional completed-batch unwind");
        }))
        .is_err()
    );
    assert!(lease.in_call.get());
    drop(lease);
    retained(&clock);
}

// A private owner snapshot allows boundary predicates to see a foreign stored
// PID/TID without actually forking or transferring a non-Send lease. It is not
// another public acquisition or a native fork qualification.
fn owner_snapshot(clock: &BackedgeClock, tid: i64, admission: Admission) -> ClockLease {
    ClockLease {
        clock: clock.clone(),
        tid,
        in_call: Cell::new(admission == Admission::Batch),
        admitted_work: 1,
        admission: Cell::new(admission),
        _thread: PhantomData,
    }
}

#[test]
fn batch_entry_rejects_simulated_foreign_pid_and_tid_without_mutation() {
    for foreign_pid in [false, true] {
        let mut clock = Data::new();
        if foreign_pid {
            Arc::get_mut(&mut clock.0.inner).unwrap().pid ^= 0x8000_0000;
        }
        clock.inner.active.store(true, Ordering::Release);
        let tid = if foreign_pid {
            thread_id()
        } else {
            thread_id() + 1
        };
        let lease = owner_snapshot(&clock, tid, Admission::Fresh);
        let before = snapshot(&clock);
        assert!(matches!(
            unsafe { lease.begin_batch(1, 1) },
            Err(ClockError::Owner)
        ));
        assert!(matches!(lease.begin_call(), Err(ClockError::Owner)));
        assert_eq!(lease.admission.get(), Admission::Fresh);
        assert!(!lease.in_call.get());
        assert_eq!(snapshot(&clock), before);
        drop(lease);
        retained(&clock);
    }
}

#[test]
fn batch_finish_rechecks_simulated_foreign_owner_and_retains_latches() {
    for foreign_pid in [false, true] {
        let original = Data::new();
        let mut changed = Data::new();
        if foreign_pid {
            Arc::get_mut(&mut changed.0.inner).unwrap().pid ^= 0x8000_0000;
        }
        changed.inner.active.store(true, Ordering::Release);
        let lease = unsafe { original.acquire(1, 1) }.unwrap();
        let tid = if foreign_pid {
            thread_id()
        } else {
            thread_id() + 1
        };
        let changed_owner = owner_snapshot(&changed, tid, Admission::Batch);
        let mut batch = unsafe { lease.begin_batch(1, 1) }.unwrap();
        batch.begin_call().unwrap().returned();
        // Replace only the private owner snapshot after real protocol
        // completion; no mutation through a live shared reference occurs.
        batch.lease = &changed_owner;
        let before = snapshot(&changed);
        assert_eq!(batch.finish(), Err(ClockError::Owner));
        assert!(lease.in_call.get() && changed_owner.in_call.get());
        assert_eq!(changed_owner.admission.get(), Admission::Batch);
        assert_eq!(snapshot(&changed), before);
        drop(changed_owner);
        drop(lease);
        retained(&original);
        retained(&changed);
    }
}
