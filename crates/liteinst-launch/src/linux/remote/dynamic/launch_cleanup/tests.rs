//! Pure channel/state models only; none is a native cleanup receipt proof.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind, panic_any};

const ORIGINAL: &str = "original runtime source refusal";
const WAIT: Duration = Duration::from_millis(1);

fn pending() -> (
    DynamicRuntimeLaunchFailure,
    Sender<Result<DynamicCleanup, LaunchError>>,
    Arc<AtomicBool>,
) {
    let cancel = Arc::new(AtomicBool::new(false));
    let (sender, done) = channel();
    let failure = DynamicRuntimeLaunchFailure {
        error: GateError::Refused(ORIGINAL),
        cleanup: Some({
            let mut prepared = PreparedCleanup::new();
            cancel.store(true, Ordering::Release);
            prepared.0.started = true;
            prepared.0.before_ready = Some(BeforeReadyCleanup {
                cancel: Arc::clone(&cancel),
                done,
            });
            prepared.0
        }),
    };
    (failure, sender, cancel)
}

fn original(failure: &DynamicRuntimeLaunchFailure) {
    assert!(matches!(failure.error(), GateError::Refused(value) if *value == ORIGINAL));
}

#[test]
fn runtime_launch_cleanup_not_started_is_not_a_receipt() {
    let mut failure = DynamicRuntimeLaunchFailure::not_started(GateError::Refused(ORIGINAL));
    original(&failure);
    assert!(matches!(
        failure.cleanup_status(),
        DynamicRuntimeCleanupStatus::NotStarted
    ));
    assert!(matches!(
        failure.wait_cleanup(WAIT).unwrap(),
        DynamicRuntimeCleanupStatus::NotStarted
    ));
    original(&failure);

    let cancel = Arc::new(AtomicBool::new(false));
    let (sender, done) = channel();
    let mut failed_spawn = PreparedCleanup::new().finish_launch(OwnedLaunchFailure::after_spawn(
        LaunchError::Invalid("actual spawn failed"),
        Arc::clone(&cancel),
        done,
        false,
    ));
    assert!(cancel.load(Ordering::Acquire));
    assert!(matches!(
        failed_spawn.wait_cleanup(WAIT).unwrap(),
        DynamicRuntimeCleanupStatus::NotStarted
    ));
    assert!(
        sender
            .send(Ok(DynamicCleanup { reaped: Vec::new() }))
            .is_err()
    );
    assert!(matches!(
        failed_spawn.error(),
        GateError::Control(LaunchError::Invalid("actual spawn failed"))
    ));

    struct NeverCalled {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl crate::selected::InstructionProvider for NeverCalled {
        fn decide(
            &mut self,
            _input: &crate::selected::SelectedInput,
        ) -> Result<crate::selected::ProviderDecision, crate::selected::SemanticsError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(crate::selected::SemanticsError::ScriptMismatch)
        }
    }
    impl Drop for NeverCalled {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let options = DynamicRuntimeOptions {
        limits: DynamicAdmissionLimits {
            source_fact_bytes: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: actual public prevalidation rejects before any native owner,
    // path access or application effect; this is not a launched native fixture.
    let result = unsafe {
        DynamicAdmissionSession::launch_runtime_with_cleanup(
            &LaunchCommand::new("unused-invalid-runtime-options"),
            options,
            NeverCalled {
                calls: Arc::clone(&calls),
                drops: Arc::clone(&drops),
            },
            WAIT,
        )
    };
    let mut failure = match result {
        Err(failure) => failure,
        Ok(_) => panic!("invalid limits unexpectedly created a runtime session"),
    };
    assert!(matches!(
        failure.error(),
        GateError::Refused("invalid dynamic admission lifetime bounds")
    ));
    assert!(matches!(
        failure.cleanup_status(),
        DynamicRuntimeCleanupStatus::NotStarted
    ));
    assert!(matches!(
        failure.wait_cleanup(WAIT).unwrap(),
        DynamicRuntimeCleanupStatus::NotStarted
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn runtime_launch_cleanup_timeout_preserves_original_receiver_and_error() {
    let (mut failure, sender, cancel) = pending();
    assert!(cancel.load(Ordering::Acquire));
    for _ in 0..2 {
        assert!(matches!(
            failure.wait_cleanup(WAIT),
            Err(LaunchError::Timeout(
                "dynamic cleanup remains owned by tracer"
            ))
        ));
        assert!(matches!(
            failure.cleanup_status(),
            DynamicRuntimeCleanupStatus::Pending
        ));
        original(&failure);
    }
    sender
        .send(Ok(DynamicCleanup {
            reaped: vec![17, 19],
        }))
        .unwrap();
    let DynamicRuntimeCleanupStatus::Complete(receipt) = failure.wait_cleanup(WAIT).unwrap() else {
        panic!("the original receiver did not retain its queued result");
    };
    assert_eq!(receipt.reaped, [17, 19]);
    original(&failure);
}

#[test]
fn runtime_launch_cleanup_caches_actual_success_and_failure() {
    let (mut complete, sender, _) = pending();
    sender
        .send(Ok(DynamicCleanup { reaped: vec![23] }))
        .unwrap();
    for _ in 0..2 {
        let DynamicRuntimeCleanupStatus::Complete(receipt) = complete.wait_cleanup(WAIT).unwrap()
        else {
            panic!("complete result was not cached");
        };
        assert_eq!(receipt.reaped, [23]);
        original(&complete);
    }
    assert!(
        sender
            .send(Ok(DynamicCleanup { reaped: vec![29] }))
            .is_err()
    );

    let (mut failed, sender, _) = pending();
    sender
        .send(Err(LaunchError::Invalid("physical cleanup proof failed")))
        .unwrap();
    for _ in 0..2 {
        assert!(matches!(
            failed.wait_cleanup(WAIT).unwrap(),
            DynamicRuntimeCleanupStatus::Failed(LaunchError::Invalid(
                "physical cleanup proof failed"
            ))
        ));
        original(&failed);
    }

    // A data-only Session exercises the post-Ready receiver ownership variant.
    // It has no native Owner, command consumer, process, pin or release authority.
    let (commands, _requests) = channel();
    let (sender, done) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let session = DynamicSession {
        pid: 0,
        initial: DynamicEvent {
            tid: 0,
            task: None,
            kind: DynamicEventKind::Exited { code: 0 },
            stop: None,
        },
        commands,
        cancel: Arc::clone(&cancel),
        done,
        operation_timeout: WAIT,
    };
    let mut failure = PreparedCleanup::new().finish_session(GateError::Refused(ORIGINAL), session);
    assert!(cancel.load(Ordering::Acquire));
    sender
        .send(Ok(DynamicCleanup { reaped: vec![31] }))
        .unwrap();
    let DynamicRuntimeCleanupStatus::Complete(receipt) = failure.wait_cleanup(WAIT).unwrap() else {
        panic!("post-Ready original receiver was not retained");
    };
    assert_eq!(receipt.reaped, [31]);
    original(&failure);
}

#[test]
fn runtime_launch_cleanup_disconnect_is_not_complete() {
    let (mut failure, sender, _) = pending();
    drop(sender);
    for _ in 0..2 {
        assert!(matches!(
            failure.wait_cleanup(WAIT).unwrap(),
            DynamicRuntimeCleanupStatus::Disconnected
        ));
        original(&failure);
    }
}

#[test]
fn runtime_launch_cleanup_rejects_invalid_wait_without_consuming() {
    let (mut failure, sender, _) = pending();
    for timeout in [Duration::ZERO, Duration::from_secs(31)] {
        assert!(matches!(
            failure.wait_cleanup(timeout),
            Err(LaunchError::Invalid(_))
        ));
        assert!(matches!(
            failure.cleanup_status(),
            DynamicRuntimeCleanupStatus::Pending
        ));
        original(&failure);
    }
    sender
        .send(Ok(DynamicCleanup { reaped: vec![37] }))
        .unwrap();
    let DynamicRuntimeCleanupStatus::Complete(receipt) = failure.wait_cleanup(WAIT).unwrap() else {
        panic!("invalid wait consumed the original receipt");
    };
    assert_eq!(receipt.reaped, [37]);
}

#[test]
fn runtime_launch_cleanup_drop_cancels_without_waiting() {
    let (failure, sender, cancel) = pending();
    assert!(cancel.load(Ordering::Acquire));
    // No sender result exists. Dropping must not wait for one.
    drop(failure);
    assert!(cancel.load(Ordering::Acquire));
    assert!(
        sender
            .send(Ok(DynamicCleanup { reaped: Vec::new() }))
            .is_err()
    );
}

#[test]
fn runtime_launch_cleanup_provider_panic_observes_prior_cancel() {
    struct ProviderDrop {
        cancel: Arc<AtomicBool>,
        seen: Arc<AtomicBool>,
        payload: Arc<u64>,
    }
    impl Drop for ProviderDrop {
        fn drop(&mut self) {
            assert!(self.cancel.load(Ordering::Acquire));
            self.seen.store(true, Ordering::Release);
            panic_any(Arc::clone(&self.payload));
        }
    }
    fn fail(
        provider: ProviderDrop,
        done: Receiver<Result<DynamicCleanup, LaunchError>>,
    ) -> Result<(), DynamicRuntimeLaunchFailure> {
        let failure = PreparedCleanup::new().finish_launch(OwnedLaunchFailure::after_spawn(
            LaunchError::Invalid(ORIGINAL),
            Arc::clone(&provider.cancel),
            done,
            true,
        ));
        // This mirrors return-value creation before parameter destruction.
        // The destructor's panic is not caught or converted by the constructor.
        Err(failure)
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicBool::new(false));
    let payload = Arc::new(0x1234_u64);
    let (_sender, done) = channel();
    let panic = catch_unwind(AssertUnwindSafe(|| {
        fail(
            ProviderDrop {
                cancel: Arc::clone(&cancel),
                seen: Arc::clone(&seen),
                payload: Arc::clone(&payload),
            },
            done,
        )
    }))
    .unwrap_err();
    assert!(cancel.load(Ordering::Acquire));
    assert!(seen.load(Ordering::Acquire));
    assert!(Arc::ptr_eq(
        panic.downcast_ref::<Arc<u64>>().unwrap(),
        &payload
    ));
}
